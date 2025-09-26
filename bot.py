# --------- KIRJASTOT ----------
import discord
from discord.ext import commands, tasks
import os, json, random, time, re, aiohttp
from datetime import datetime
from dotenv import load_dotenv   # ympäristömuuttujien lataus

# ---------------- ASETUKSET ----------------
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

# --- Linkki- ja kuvamoderointi-asetukset ---
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
BLOCKED_DOMAINS = [
    "grabify.link",
    "iplogger.org",
    "2no.co",
    "yip.su",
    "pornhub.com",
    "alivegore.com"
]

# --- Sightengine-asetukset ---
SIGHTENGINE_USER = os.getenv("SIGHTENGINE_USER")
SIGHTENGINE_SECRET = os.getenv("SIGHTENGINE_SECRET")
SIGHTENGINE_URL = os.getenv("SIGHTENGINE_URL")
SIGHTENGINE_MODELS = os.getenv("SIGHTENGINE_MODELS")

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

LEVELS_FILE = "levels.json"
WIPE_FILE = "wipe.json"

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

levels = load_json(LEVELS_FILE, {})
wipecfg = load_json(WIPE_FILE, {})

def xp_to_next(lvl: int) -> int:
    return 5 * lvl * lvl + 50 * lvl + 100

async def is_bad_url(url: str) -> bool:
    """Tarkistaa URLin Safe Browsingilla ja estolistalla."""
    for domain in BLOCKED_DOMAINS:
        if domain in url.lower():
            return True

    if not SAFE_BROWSING_KEY:
        return False

    payload = {
        "client": {"clientId": "kalevala-bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_KEY}", json=payload) as resp:
            data = await resp.json()
            return bool(data.get("matches"))

async def is_nsfw_image(img_url: str) -> bool:
    """Tarkistaa kuvan Sightengine-APIn avulla."""
    if not SIGHTENGINE_USER or not SIGHTENGINE_SECRET:
        return False

    params = {
        'models': SIGHTENGINE_MODELS,
        'api_user': SIGHTENGINE_USER,
        'api_secret': SIGHTENGINE_SECRET,
        'url': img_url
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(SIGHTENGINE_URL, params=params) as resp:
            data = await resp.json()
            print("API-vastaus:", data)  # DEBUG

            if "nudity" in data:
                nudity = data["nudity"]
                if nudity.get("sexual_activity", 0) > 0.5 or nudity.get("sexual_display", 0) > 0.5:
                    return True

            if "recreational_drug" in data and data["recreational_drug"].get("prob", 0) > 0.5:
                return True

            if "alcohol" in data and data["alcohol"].get("prob", 0) > 0.5:
                return True
            if "gambling" in data and data["gambling"].get("prob", 0) > 0.5:
                return True
            if "violence" in data and data["violence"].get("prob", 0) > 0.5:
                return True
            if "self-harm" in data and data["self-harm"].get("prob", 0) > 0.5:
                return True

    return False

@bot.event
async def on_ready():
    print(f"✅ Botti käynnistyi: {bot.user}")
    wipe_watch.start()

@bot.event
async def on_member_join(member: discord.Member):
    role = discord.utils.get(member.guild.roles, name="Pelaaja")
    if role:
        try:
            await member.add_roles(role, reason="Automaattinen aloitusrooli")
        except Exception:
            pass
    channel = discord.utils.get(member.guild.text_channels, name="yleinen-jauhanta")
    if channel:
        await channel.send(f"👋 Tervetuloa KalevalaPortin Rust-serverille, {member.mention}! ")

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not isinstance(message.channel, discord.TextChannel):
        return await bot.process_commands(message)

    print("DEBUG: viesti vastaanotettu", message.content, message.attachments)

    # Linkkien tarkistus
    urls = re.findall(r'https?://\S+', message.content)
    for url in urls:
        if await is_bad_url(url):
            try:
                await message.delete()
                await message.channel.send(
                    f"⚠️ {message.author.mention}, linkkisi estettiin epäilyttävänä.",
                    delete_after=6
                )
            except Exception:
                pass
            return

    # Kuvien / liitteiden tarkistus (lisätty GIF-tuki)
    for attachment in message.attachments:
        print("DEBUG: attachment", attachment.filename, attachment.content_type)
        if (attachment.content_type and attachment.content_type.startswith("image")) \
           or attachment.filename.lower().endswith(".gif"):
            if await is_nsfw_image(attachment.url):
                try:
                    await message.delete()
                    await message.channel.send(
                        f"🚫 {message.author.mention}, kuva poistettiin sääntöjen rikkomisen vuoksi.",
                        delete_after=6
                    )
                except Exception:
                    pass
                return

    # XP-logiikka
    uid = str(message.author.id)
    u = levels.get(uid, {"xp": 0, "level": 0, "last": 0})
    now = time.time()

    if now - u.get("last", 0) >= 60:
        gained = random.randint(5, 10)
        u["xp"] += gained
        u["last"] = now

        needed = xp_to_next(u["level"])
        if u["xp"] >= needed:
            u["xp"] -= needed
            u["level"] += 1
            await message.channel.send(
                f"🔼 {message.author.mention} nousi tasolle **{u['level']}**! 🎉"
            )

        levels[uid] = u
        save_json(LEVELS_FILE, levels)

    await bot.process_commands(message)

# (Komennot ja wipe-osio pysyvät samana kuin aiemmin)

# Lopussa aja:
bot.run(TOKEN)
