import os
import json
import requests
from flask import Flask, redirect, request, session, render_template
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
DISCORD_API_BASE = "https://discord.com/api"

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "server_config.json")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/discord-login")
def discord_login():
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds"
    }
    url = f"{DISCORD_API_BASE}/oauth2/authorize?{requests.compat.urlencode(params)}"
    return redirect(url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400

    # Exchange code for access token
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": "identify guilds"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_res = requests.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers)
    access_token = token_res.json().get("access_token")
    if not access_token:
        return "Failed to get access token", 400

    # Fetch user info
    user_res = requests.get(f"{DISCORD_API_BASE}/users/@me", headers={"Authorization": f"Bearer {access_token}"})
    user = user_res.json()
    session["user"] = user
    session["access_token"] = access_token

    # Fetch user guilds (store only IDs)
    guilds_res = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers={"Authorization": f"Bearer {access_token}"})
    user_guilds = guilds_res.json()
    session["user_guild_ids"] = [str(g["id"]) for g in user_guilds]

    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    user = session["user"]
    user_guild_ids = session.get("user_guild_ids", [])

    # Load bot guild info
    with open(CONFIG_PATH) as f:
        server_config = json.load(f)

    shared_servers = []
    for gid in user_guild_ids:
        if gid in server_config:
            config = server_config[gid]
            shared_servers.append({
                "id": gid,
                "name": config.get("name", "Unknown Server"),
                "icon": config.get("icon")
            })

    return render_template("dashboard.html", user=user, shared_servers=shared_servers)


@app.route("/server/<server_id>")
def manage_server(server_id):
    if "user" not in session or "access_token" not in session:
        return redirect("/login")

    user = session["user"]
    user_id = int(user["id"])

    # Check if user is in this guild
    user_guild_ids = session.get("user_guild_ids", [])
    if server_id not in user_guild_ids:
        return render_template("403.html"), 403

    # Load server config
    with open(CONFIG_PATH) as f:
        server_config = json.load(f)

    guild_config = server_config.get(server_id)
    if not guild_config:
        return "❌ Server config not found.", 404

    owner_id = guild_config.get("owner_id")
    admin_role_id = guild_config.get("admin_role_id")

    # Build guild_info for template
    guild_info = {
        "id": server_id,
        "name": guild_config.get("name", "Unknown Server"),
        "icon": guild_config.get("icon")  # could be None
    }

    # Allow access if user is owner
    if owner_id and user_id == owner_id:
        return render_template("manage_server.html", user=user, server=guild_info, config=guild_config)

    # Allow access if user has admin role
    if admin_role_id:
        headers = {"Authorization": f"Bot {os.getenv('DISCORD_TOKEN_ID')}"}
        member_res = requests.get(f"https://discord.com/api/v10/guilds/{server_id}/members/{user_id}", headers=headers)
        if member_res.status_code == 200:
            member_data = member_res.json()
            roles = [int(r) for r in member_data.get("roles", [])]
            if int(admin_role_id) in roles:
                return render_template("manage_server.html", user=user, server=guild_info, config=guild_config)

    return redirect("/denied")

@app.route("/denied")
def denied():
    return render_template("403.html"), 403


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)


