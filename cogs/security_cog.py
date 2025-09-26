import discord
from discord.ext import commands, tasks
import aiohttp
import asyncio
import re
import json
import os
import tldextract
import base64
import time
from datetime import timedelta

CONFIG_FILE = "server_config.json"
METRICS_FILE = "server_metrics.json"
OFFENSES_FILE = "offenses.json"

# --- Regex for masked [text](url) and raw URLs ---
URL_REGEX = re.compile(
    r'\[.*?\]\((https?://[^\s]+)\)|'  # masked link
    r'(https?://[^\s]+)'              # raw url
)

# --- JSON helpers ---
def load_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# --- Offenses helpers ---
def load_offenses():
    return load_json(OFFENSES_FILE)

def save_offenses(data):
    save_json(OFFENSES_FILE, data)

# --- Global tracking ---
handled_by_security = set()

def encode_url_to_vt_id(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")

def extract_urls(text: str):
    matches = URL_REGEX.findall(text)
    urls = []
    for m in matches:
        if isinstance(m, tuple):
            urls.append(m[0] or m[1])
        else:
            urls.append(m)
    return [u for u in urls if u]

class SecurityCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.link_cache = {}
        self.CACHE_EXPIRY = 60 * 60
        self.server_metrics = load_json(METRICS_FILE)
        self.GLOBAL_BLACKLISTED_DOMAINS = ["grabify.link", "iplogger.org", "bmwforum.co", "yip.su", "pornhub.com"]
        self.GLOBAL_BLACKLISTED_KEYWORDS = ["Free Nitro", "nitro giveaway", "free crypto", "btc giveaway", "free robux", "Robux giveaway"]
        self.GLOBAL_ALLOWED_DOMAINS = ["youtube.com", "x.com", "tiktok.com"]
        self.VT_API_KEY = os.getenv("VT_API_KEY")

    # --- Config helpers ---
    def load_config(self):
        return load_json(CONFIG_FILE)

    def get_alert_channel(self, guild: discord.Guild):
        config = self.load_config()
        alert_id = config.get(str(guild.id), {}).get("alert_channel_id")
        return guild.get_channel(alert_id) if alert_id else None

    def get_admin_role(self, guild: discord.Guild):
        config = self.load_config()
        role_id = config.get(str(guild.id), {}).get("admin_role_id")
        return guild.get_role(role_id) if role_id else None

    def get_dangerous_perms(self, guild: discord.Guild):
        config = self.load_config()
        return set(config.get(str(guild.id), {}).get("dangerous_perms", [
            "administrator","ban_members","kick_members","manage_guild","manage_roles","manage_webhooks"
        ]))

    # --- Metrics ---
    def init_guild_metrics(self, guild_id):
        gid = str(guild_id)
        if gid not in self.server_metrics:
            self.server_metrics[gid] = {"links_removed": 0, "warnings_issued": 0, "users_banned": 0}
            save_json(METRICS_FILE, self.server_metrics)

    def update_metric(self, guild_id, metric_name, amount=1):
        self.init_guild_metrics(guild_id)
        self.server_metrics[str(guild_id)][metric_name] += amount
        save_json(METRICS_FILE, self.server_metrics)

    # --- Offenses ---
    def init_user_offenses(self, guild_id, user_id):
        data = load_offenses()
        gid = str(guild_id)
        uid = str(user_id)
        if gid not in data:
            data[gid] = {}
        if uid not in data[gid]:
            data[gid][uid] = 0
        save_offenses(data)

    async def warn_user(self, guild: discord.Guild, user: discord.Member, alert_channel: discord.TextChannel, reason: str):
        data = load_offenses()
        gid = str(guild.id)
        uid = str(user.id)
        self.init_user_offenses(gid, uid)

        data = load_offenses()
        data[gid][uid] += 1
        warnings = data[gid][uid]

        config = self.load_config()
        guild_config = config.get(gid, {})
        ban_threshold = guild_config.get("ban_threshold", 3)

        if ban_threshold == 3:
            if warnings == 1:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=1)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 1 hour."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 1 hour.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            if warnings == 2:
                # Kick on Second warning
                try:
                    await user.kick(reason=reason)
                except Exception as e:
                    print(f"Failed to kick {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been kicked in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been automatically kicked. If you send a malicious link once more, you will be banned."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Automatically kicked.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
                # Autoban check
                if warnings >= ban_threshold:
                    try:
                        await guild.ban(user, reason=f"Reached {ban_threshold} warnings")
                        self.update_metric(guild.id, "users_banned")
                        if alert_channel:
                            embed = discord.Embed(
                                title="User Banned",
                                description=f"{user} was automatically banned after reaching {ban_threshold} warnings.",
                                color=discord.Color.red()
                            )
                        admin_role = self.get_admin_role(guild)
                        if admin_role:
                            await alert_channel.send(content=admin_role.mention, embed=embed)
                        else:
                            await alert_channel.send(embed=embed)
                    except Exception as e:
                        print(f"Failed to ban {user}: {e}")
        elif ban_threshold == 1:
            # Autoban check
            if warnings >= ban_threshold:
                try:
                    await guild.ban(user, reason=f"Reached {ban_threshold} warnings")
                    self.update_metric(guild.id, "users_banned")
                    if alert_channel:
                        embed = discord.Embed(
                            title="User Banned",
                            description=f"{user} was automatically banned after reaching {ban_threshold} warnings.",
                            color=discord.Color.red()
                        )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
                except Exception as e:
                    print(f"Failed to ban {user}: {e}")
        elif ban_threshold == 2:
            if warnings == 1:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=1)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 1 hour."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 1 hour.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            # Autoban check
            if warnings >= ban_threshold:
                try:
                    await guild.ban(user, reason=f"Reached {ban_threshold} warnings")
                    self.update_metric(guild.id, "users_banned")
                    if alert_channel:
                        embed = discord.Embed(
                            title="User Banned",
                            description=f"{user} was automatically banned after reaching {ban_threshold} warnings.",
                            color=discord.Color.red()
                        )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
                except Exception as e:
                    print(f"Failed to ban {user}: {e}")
        elif ban_threshold == 4:
            if warnings == 1:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=1)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 1 hour."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 1 hour.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            if warnings == 2:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=2)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 2 hours."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 2 hours.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            if warnings == 3:
                # Kick on third warning
                try:
                    await user.kick(reason=reason)
                except Exception as e:
                    print(f"Failed to kick {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been kicked in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been automatically kicked. If you send a malicious link once more, you will be banned."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Automatically kicked.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
                # Autoban check
                if warnings >= ban_threshold:
                    try:
                        await guild.ban(user, reason=f"Reached {ban_threshold} warnings")
                        self.update_metric(guild.id, "users_banned")
                        if alert_channel:
                            embed = discord.Embed(
                                title="User Banned",
                                description=f"{user} was automatically banned after reaching {ban_threshold} warnings.",
                                color=discord.Color.red()
                            )
                        admin_role = self.get_admin_role(guild)
                        if admin_role:
                            await alert_channel.send(content=admin_role.mention, embed=embed)
                        else:
                            await alert_channel.send(embed=embed)
                    except Exception as e:
                        print(f"Failed to ban {user}: {e}")
        elif ban_threshold == 5:
            if warnings == 1:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=1)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 1 hour."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 1 hour.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            if warnings == 2:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=2)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 2 hours."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 2 hours.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
            if warnings == 3:
                # Timeout on first warning
                try:
                    duration = timedelta(hours=2)
                    await user.timeout_for(duration, reason=reason)
                except Exception as e:
                    print(f"Failed to timeout {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been warned in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been timed out for 2 hours."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Timed out for 2 hours.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)

            if warnings == 4:
                # Kick on third warning
                try:
                    await user.kick(reason=reason)
                except Exception as e:
                    print(f"Failed to kick {user}: {e}")

                # DM user
                try:
                    await user.send(
                        f"⚠️ You have been kicked in **{guild.name}** for: {reason}. "
                        f"Warning {warnings}/{ban_threshold}. "
                        f"You have been automatically kicked. If you send a malicious link once more, you will be banned."
                    )
                except:
                    pass

                # Alert channel
                if alert_channel:
                    embed = discord.Embed(
                        title="User Warned & Timed Out",
                        description=f"{user} has been warned for: {reason}. "
                                    f"Warning {warnings}/{ban_threshold}\n"
                                    f"⏱️ Automatically kicked.",
                        color=discord.Color.orange()
                    )
                    admin_role = self.get_admin_role(guild)
                    if admin_role:
                        await alert_channel.send(content=admin_role.mention, embed=embed)
                    else:
                        await alert_channel.send(embed=embed)
                # Autoban check
                if warnings >= ban_threshold:
                    try:
                        await guild.ban(user, reason=f"Reached {ban_threshold} warnings")
                        self.update_metric(guild.id, "users_banned")
                        if alert_channel:
                            embed = discord.Embed(
                                title="User Banned",
                                description=f"{user} was automatically banned after reaching {ban_threshold} warnings.",
                                color=discord.Color.red()
                            )
                        admin_role = self.get_admin_role(guild)
                        if admin_role:
                            await alert_channel.send(content=admin_role.mention, embed=embed)
                        else:
                            await alert_channel.send(embed=embed)
                    except Exception as e:
                        print(f"Failed to ban {user}: {e}")
            
        save_offenses(data)

    # --- Token/credentials check ---
    def contains_token_or_credentials(self, content: str) -> bool:
        token_pattern = re.compile(r"([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})")
        password_pattern = re.compile(r"(password\s*[:=]\s*\S+)", re.IGNORECASE)
        return bool(token_pattern.search(content) or password_pattern.search(content))

    # --- VirusTotal ---
    async def get_vt_url_report(self, url: str):
        if not self.VT_API_KEY:
            return None
        now = time.time()
        cache_entry = self.link_cache.get(url)
        if cache_entry:
            ts, data = cache_entry
            if now - ts < self.CACHE_EXPIRY:
                return data
        vt_id = encode_url_to_vt_id(url)
        endpoint = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
        headers = {"x-apikey": self.VT_API_KEY}
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(endpoint, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.link_cache[url] = (now, data)
                        return data
                    self.link_cache[url] = (now, None)
                    return None
        except Exception as e:
            print(f"VirusTotal request failed for {url}: {e}")
            return None

    # --- Message handler ---
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        if message.id in handled_by_security:
            return
        handled_by_security.add(message.id)

        guild_id = message.guild.id
        self.init_guild_metrics(guild_id)
        alert_channel = self.get_alert_channel(message.guild)

        # --- Invite link ---
        if any(word.startswith("https://discord.gg/") for word in message.content.split()):
            try: await message.delete()
            except: pass
            self.update_metric(guild_id, "warnings_issued")
            await self.warn_user(message.guild, message.author, alert_channel, "Sharing server invites")

        # --- Token/credentials ---
        if self.contains_token_or_credentials(message.content):
            try: await message.delete()
            except: pass
            self.update_metric(guild_id, "warnings_issued")
            await self.warn_user(message.guild, message.author, alert_channel, "Sharing credentials or tokens")

        # --- Keyword check ---
        config = self.load_config()
        guild_config = config.get(str(guild_id), {})
        combined_keywords = set(self.GLOBAL_BLACKLISTED_KEYWORDS + guild_config.get("blacklisted_keywords", []))
        for keyword in combined_keywords:
            if keyword.lower() in message.content.lower():
                try: await message.delete()
                except: pass
                self.update_metric(guild_id, "warnings_issued")
                await self.warn_user(message.guild, message.author, alert_channel, f"Using blacklisted keyword `{keyword}`")

        # --- URL check ---
        urls = extract_urls(message.content)
        combined_domains = set(self.GLOBAL_BLACKLISTED_DOMAINS + guild_config.get("blacklisted_domains", []))
        for url in urls:
            extracted = tldextract.extract(url)
            domain = extracted.registered_domain
            full_domain = f"{extracted.subdomain}.{domain}" if extracted.subdomain else domain

            if domain in self.GLOBAL_ALLOWED_DOMAINS:
                continue

            if domain in combined_domains or any(domain.endswith(bad) for bad in combined_domains):
                try: await message.delete()
                except: pass
                self.update_metric(guild_id, "links_removed")
                await self.warn_user(message.guild, message.author, alert_channel, f"Sent blacklisted domain `{full_domain}`")
                return

            # VirusTotal check
            vt_data = await self.get_vt_url_report(url)
            if vt_data:
                malicious_votes = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                if malicious_votes > 0:
                    try: await message.delete()
                    except: pass
                    self.update_metric(guild_id, "links_removed")
                    await self.warn_user(message.guild, message.author, alert_channel, f"Sent malicious URL `{url}` ({malicious_votes} engines flagged)")
                    return

    # --- Guild join / webhooks ---
    @commands.Cog.listener()
    async def on_guild_join(self, guild):
        self.init_guild_metrics(guild.id)
        await self.remove_unauthorized_webhooks(guild)

    async def remove_unauthorized_webhooks(self, guild: discord.Guild):
        try:
            for webhook in await guild.webhooks():
                if webhook.user is None:
                    await webhook.delete()
        except:
            pass

    # --- Metrics command ---
    @commands.command(name="metrics")
    async def metrics(self, ctx):
        self.init_guild_metrics(ctx.guild.id)
        data = self.server_metrics[str(ctx.guild.id)]
        embed = discord.Embed(title="Server Security Metrics", color=discord.Color.green())
        embed.add_field(name="Links Removed", value=str(data["links_removed"]))
        embed.add_field(name="Warnings Issued", value=str(data["warnings_issued"]))
        embed.add_field(name="Users Banned/Timed Out", value=str(data["users_banned"]))
        await ctx.send(embed=embed)

    # --- Webhook monitor ---
    @tasks.loop(hours=1)
    async def webhook_monitor(self):
        for guild in self.bot.guilds:
            await self.remove_unauthorized_webhooks(guild)

    @commands.Cog.listener()
    async def on_ready(self):
        if not self.webhook_monitor.is_running():
            self.webhook_monitor.start()


def setup(bot):
    print("Running SecurityCog setup()")
    bot.add_cog(SecurityCog(bot))
