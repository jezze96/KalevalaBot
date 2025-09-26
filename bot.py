# --------- KIRJASTOT ----------
import discord
from discord.ext import commands, tasks
import os, json, random, time, re, aiohttp
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

# ---------------- ASETUKSET ----------------
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

# --- Linkki- ja kuvamoderointi-asetukset ---
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Huom. käytä *host*-täsmäystä (ei pelkkää substringiä).
BLOCKED_DOMAINS = {
    "grabify.link",
    "iplogger.org",
    "2no.co",
    "yip.su",
    "pornhub.com",
    "xvideos.com",
    "alivegore.com",
}

# --- Sightengine-asetukset ---
SIGHTENGINE_USER = os.getenv("SIGHTENGINE_USER")
SIGHTENGINE_SECRET = os.getenv("SIGHTENGINE_SECRET")
SIGHTENGINE_URL = os.getenv("SIGHTENGINE_URL")           # esim. https://api.sightengine.com/1.0/check.json
SIGHTENGINE_MODELS = os.getenv("SIGHTENGINE_MODELS")     # esim. nudity-2.1,alcohol,recreational_drug,...

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

LEVELS_FILE = "levels.json"
WIPE_FILE = "wipe.json"

# ---------------- JSON-TIEDOSTOJEN LATAUS ----------------
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


# ---------------- APU: TEKSTISUODATUS ----------------
# Kevyt suomi+englanti kirosanat + seksuaalinen sisältö (stemmejä myös yhdyssanojen varalle).
BAD_WORD_STEMS = {
    # FI kirosanat
    "vittu", "vitun", "perke", "saatan", "helvet", "paska", "kusip", "huora", "hor", "homott", "homo",
    "idioot", "lutka", "perse", "huor", "runkk", "runkk", "huoritt",
    # EN kirosanat
    "fuck", "shit", "bitch", "bastard", "asshole", "asshat", "dick", "prick", "cunt", "slut", "whore",
    # Seksuaalinen / aikuissisältö (yleisiä termejä – tarkoitus moderoida ei sallituissa kanavissa)
    "porno", "porn", "sex", "seks", "seksi", "nude", "naked", "boob", "titty", "penis", "pillu", "kyrv", "kyrp",
    "vagina", "clit", "orgas", "cum", "jizz", "bj", "blowjob", "anal", "anals", "dp ", "bdsm", "fetish",
    "rape", "raiska", "bestial", "incest",
}
# Sana-rajatettu lista (tarkempi osuma yleisimmille)
BAD_WORDS_STRICT = {
    "vittu", "vitun", "perkele", "saatana", "helvetti", "paska", "huora", "homo",
    "fuck", "shit", "bitch", "slut", "whore", "porn", "sex", "seksi", "nude",
}

WORD_BOUNDARY_RE = re.compile(r"\b", re.IGNORECASE)

def normalize_text(s: str) -> str:
    # pienet kirjaimet + poista kaikki paitsi kirjaimet ja numerot (yhteen tarkastelua varten)
    return re.sub(r"[^a-z0-9äöå]+", "", s.lower())

def contains_bad_text(message_text: str) -> str | None:
    """
    Palauttaa osuman (merkkijonon) jos viesti sisältää kiellettyä kieltä, muuten None.
    Tarkistaa sekä sanatasolla että lyhyillä stemeillä yhdyssanojen varalta.
    """
    text = message_text.lower()

    # 1) Tiukka sanaosuma
    for w in BAD_WORDS_STRICT:
        # \b ei toimi hyvin ä/ö/å kanssa kaikkialla -> käytä välimerkki/raja -tarkastelua
        if re.search(rf"(^|[^a-zåäö]){re.escape(w)}([^a-zåäö]|$)", text):
            return w

    # 2) Normalisoitu stemmihaku (poistaa välimerkit ja välit)
    flat = normalize_text(text)
    for stem in BAD_WORD_STEMS:
        if stem in flat:
            return stem

    return None


# ---------------- API-TARKISTUKSET ----------------
def host_in_blocklist(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().lstrip(".")
        if not host:
            return False
        # estä myös alidomainit: *.domain.com
        for bad in BLOCKED_DOMAINS:
            if host == bad or host.endswith("." + bad):
                return True
        return False
    except Exception:
        return False


async def is_bad_url(url: str) -> bool:
    """Tarkistaa URLin estolistalla + Safe Browsingilla."""
    if host_in_blocklist(url):
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
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_KEY}", json=payload) as resp:
                data = await resp.json()
                return bool(data.get("matches"))
    except Exception:
        # API-ongelmissa älä riko viestiä – jätä vain estämättä Safe Browsingin perusteella
        return False


async def is_nsfw_image(img_url: str) -> bool:
    """Tarkistaa kuvan Sightengine-APIn avulla."""
    if not SIGHTENGINE_USER or not SIGHTENGINE_SECRET or not SIGHTENGINE_URL:
        return False

    params = {
        'models': SIGHTENGINE_MODELS,
        'api_user': SIGHTENGINE_USER,
        'api_secret': SIGHTENGINE_SECRET,
        'url': img_url
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(SIGHTENGINE_URL, params=params) as resp:
                data = await resp.json()
                print("API-vastaus:", data)   # DEBUG – näyttää konsolissa Sightengine-JSONin

                # ---- Nudity ----
                if "nudity" in data:
                    nudity = data["nudity"]
                    if nudity.get("sexual_activity", 0) > 0.5 or nudity.get("sexual_display", 0) > 0.5:
                        return True

                # ---- Huumekuvat ----
                if "recreational_drug" in data and data["recreational_drug"].get("prob", 0) > 0.5:
                    return True

                # ---- Alkoholi / uhkapeli / väkivalta / self-harm ----
                if "alcohol" in data and data["alcohol"].get("prob", 0) > 0.5:
                    return True
                if "gambling" in data and data["gambling"].get("prob", 0) > 0.5:
                    return True
                if "violence" in data and data["violence"].get("prob", 0) > 0.5:
                    return True
                if "self-harm" in data and data["self-harm"].get("prob", 0) > 0.5:
                    return True
    except Exception:
        return False

    return False


# ---------------- KÄYNNISTYS ----------------
@bot.event
async def on_ready():
    print(f"✅ Botti käynnistyi: {bot.user}")
    wipe_watch.start()


# ---------------- TERVETULO-VIESTI ----------------
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


# ---------------- XP / LEVELIT + SUOJAUKSET ----------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not isinstance(message.channel, discord.TextChannel):
        return await bot.process_commands(message)

    print("DEBUG: viesti vastaanotettu", message.content, message.attachments)

    # 0) Kirosanat ja seksuaalinen sisältö (teksti)
    bad = contains_bad_text(message.content)
    if bad:
        try:
            await message.delete()
            await message.channel.send(
                f"⚠️ {message.author.mention}, viestisi poistettiin kielenkäytön vuoksi.",
                delete_after=6
            )
        except Exception:
            pass
        return

    # 1) Linkkien tarkistus
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

    # 2) Kuvien / GIF-liitteiden tarkistus
    for attachment in message.attachments:
        ct = (attachment.content_type or "").lower()
        fn = (attachment.filename or "").lower()
        looks_like_image = ct.startswith("image") or "gif" in ct or fn.endswith(".gif") or fn.endswith(".png") or fn.endswith(".jpg") or fn.endswith(".jpeg") or fn.endswith(".webp")
        if looks_like_image:
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

    # 3) XP-logiikka
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


# ---------------- KOMENNOT ----------------
@bot.command()
async def rank(ctx):
    u = levels.get(str(ctx.author.id), {"xp": 0, "level": 0})
    await ctx.send(
        f"🏅 {ctx.author.display_name}: taso **{u['level']}**, XP **{u['xp']}** / **{xp_to_next(u.get('level',0))}**"
    )


@bot.command()
async def top(ctx, n: int = 10):
    if not levels:
        return await ctx.send("Ei vielä pisteitä.")
    ranking = sorted(
        levels.items(),
        key=lambda kv: (kv[1].get("level", 0), kv[1].get("xp", 0)),
        reverse=True
    )[:max(1, min(25, n))]

    lines = []
    for i, (uid, u) in enumerate(ranking, start=1):
        member = ctx.guild.get_member(int(uid))
        name = member.display_name if member else uid
        lines.append(f"{i}. **{name}** — lvl {u.get('level',0)} ({u.get('xp',0)}/{xp_to_next(u.get('level',0))} XP)")
    await ctx.send("\n".join(lines))


@bot.command()
async def moi(ctx):
    await ctx.send(f"Moi {ctx.author.mention}! 😊")


@bot.command()
async def ping(ctx):
    await ctx.send("🏓 Pong!")


@bot.command()
async def rules(ctx):
    rules_text = (
        "__**KalevalaPortin säännöt / Rules**__\n"
        "1️⃣ Ei huijaamista, exploiteja, bugeja tai kolmannen osapuolen ohjelmia.\n"
        "2️⃣ Ei rasismia, uhkailua tai häirintää.\n"
        "3️⃣ Ei griefaamista.\n"
        "4️⃣ Ei liittoutumista yli 3 hengen tiimeissä.\n"
    )
    await ctx.send(rules_text)


@bot.command()
async def help(ctx):
    help_text = (
        "**Komennot:**\n"
        "`!moi`, `!ping`, `!rules`, `!serverinfo`, `!event <teksti>`, `!meme`\n"
        "`!rank`, `!top [n]`\n"
        "`!tiketti`, `!sulje`\n"
        "`!kick @user [syy]`, `!ban @user [syy]`, `!unban <id>`, `!clear <määrä>`\n"
        "`!setwipe YYYY-MM-DD HH:MM`, `!nextwipe`"
    )
    await ctx.send(help_text)


@bot.command()
async def serverinfo(ctx):
    g = ctx.guild
    embed = discord.Embed(title="📊 Discord-palvelimen tiedot", color=discord.Color.green())
    embed.add_field(name="Nimi", value=g.name, inline=True)
    embed.add_field(name="Jäseniä", value=g.member_count, inline=True)
    embed.add_field(name="Tekstikanavia", value=len(g.text_channels), inline=True)
    embed.add_field(name="Puhekanavia", value=len(g.voice_channels), inline=True)
    if g.icon:
        embed.set_thumbnail(url=g.icon.url)
    await ctx.send(embed=embed)


@bot.command()
async def event(ctx, *, teksti: str):
    await ctx.send(f"📢 **Tapahtuma:** {teksti}")


meme_list = [
    "https://imgur.com/a/YueJy8p",
    "https://imgur.com/w8e3wJO",
    "https://imgur.com/2oP0ier",
    "https://imgur.com/pdif9wA",
]


@bot.command()
async def meme(ctx):
    await ctx.send(random.choice(meme_list))


# ---------------- MODERAATIO ----------------
@bot.command()
@commands.has_permissions(kick_members=True)
async def kick(ctx, member: discord.Member, *, reason="Ei syytä annettu"):
    await member.kick(reason=reason)
    await ctx.send(f"👟 {member.mention} poistettu. Syy: {reason}")


@bot.command()
@commands.has_permissions(ban_members=True)
async def ban(ctx, member: discord.Member, *, reason="Ei syytä annettu"):
    await member.ban(reason=reason)
    await ctx.send(f"🚫 {member.mention} bännätty. Syy: {reason}")


@bot.command()
@commands.has_permissions(ban_members=True)
async def unban(ctx, user_id: int):
    user = await bot.fetch_user(user_id)
    if not user:
        return await ctx.send("❌ Käyttäjää ei löytynyt.")
    try:
        await ctx.guild.unban(user)
        await ctx.send(f"✅ Poistettu banni käyttäjältä **{user}**.")
    except Exception as e:
        await ctx.send(f"⚠️ Virhe: {e}")


@bot.command()
@commands.has_permissions(manage_messages=True)
async def clear(ctx, maara: int):
    if maara < 1:
        return await ctx.send("Anna poistettava määrä (>0).")
    deleted = await ctx.channel.purge(limit=maara + 1)
    await ctx.send(f"🧹 Poistettu {len(deleted) - 1} viestiä.", delete_after=5)


# ---------------- TIKETIT ----------------
@bot.command()
async def tiketti(ctx):
    guild = ctx.guild
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.author: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    }
    channel_name = f"tiketti-{ctx.author.name}"
    channel = await guild.create_text_channel(channel_name, overwrites=overwrites)
    await channel.send(f"👋 Hei {ctx.author.mention}! Kerro ongelma, ylläpito auttaa pian.")
    await ctx.send(f"✅ Tiketti luotu: {channel.mention}")


@bot.command()
async def sulje(ctx):
    if ctx.channel.name.startswith("tiketti-"):
        await ctx.send("🔒 Tiketti suljetaan…")
        await ctx.channel.delete()
    else:
        await ctx.send("❌ Tätä komentoa voi käyttää vain tikettikanavassa.")


# ---------------- WIPE-AJASTUS ----------------
def parse_dt(s: str):
    return datetime.strptime(s, "%Y-%m-%d %H:%M")


@bot.command()
@commands.has_permissions(manage_guild=True)
async def setwipe(ctx, pvm_klo: str, aika: str):
    try:
        when = parse_dt(f"{pvm_klo} {aika}")
    except ValueError:
        return await ctx.send("Käytä muotoa: `!setwipe YYYY-MM-DD HH:MM`")

    wipecfg["when"] = when.strftime("%Y-%m-%d %H:%M")
    wipecfg["did_24"] = False
    wipecfg["did_1"] = False
    wipecfg["did_0"] = False
    save_json(WIPE_FILE, wipecfg)

    await ctx.send(f"🗓️ Seuraava wipe asetettu: **{wipecfg['when']}**. Ilmoitukset tulevat `#ilmoitukset`-kanavaan.")


@bot.command()
async def nextwipe(ctx):
    when = wipecfg.get("when")
    if not when:
        return await ctx.send("Seuraavaa wipeä ei ole asetettu. Käytä `!setwipe YYYY-MM-DD HH:MM`.")
    dt = parse_dt(when)
    diff = dt - datetime.now()
    hrs = int(diff.total_seconds() // 3600)
    mins = int((diff.total_seconds() % 3600) // 60)
    await ctx.send(f"🕒 Seuraava wipe: **{when}** (n. {hrs} h {mins} min)")


@tasks.loop(seconds=60)
async def wipe_watch():
    when = wipecfg.get("when")
    if not when:
        return
    try:
        dt = parse_dt(when)
    except Exception:
        return

    now = datetime.now()
    ch = None
    for g in bot.guilds:
        ch = discord.utils.get(g.text_channels, name="ilmoitukset")
        if ch:
            break
    if not ch:
        return

    if not wipecfg.get("did_24") and 0 <= (dt - now).total_seconds() <= 24 * 3600:
        await ch.send(f"⏰ **24 h** seuraavaan wipeen ({when})!")
        wipecfg["did_24"] = True
        save_json(WIPE_FILE, wipecfg)

    if not wipecfg.get("did_1") and 0 <= (dt - now).total_seconds() <= 3600:
        await ch.send(f"⏰ **1 h** seuraavaan wipeen ({when})!")
        wipecfg["did_1"] = True
        save_json(WIPE_FILE, wipecfg)

    if not wipecfg.get("did_0") and 0 <= (now - dt).total_seconds() < 60:
        await ch.send("🧹 **Wipe alkaa NYT!** Onnea matkaan, selviytyjät! 💥")
        wipecfg["did_0"] = True
        save_json(WIPE_FILE, wipecfg)


# ---------------- KÄYNNISTYS ----------------
bot.run(TOKEN)
