"""
Mokosh Discord Bot
────────────────────────────────────────────
API: https://mokosh-api-9f9713bc633f.herokuapp.com
Endpoints:
  POST /analyze/messages  — text
  POST /analyze/image     — multipart image
  POST /analyze/audio     — multipart audio
  POST /analyze/video     — multipart video

Slash commands:
  /check  <text>  — analyze text (everyone)
  /settings       — configure moderation (admins only)
  /violations     — show a user's violation count (admins only)
  /reset          — reset a user's violation count (admins only)

Moderation logic (ignores API action):
  • Every harmful detection → warn in channel + post to #mokosh-log + delete message
  • violations >= BAN_VIOLATION_THRESHOLD AND confidence >= BAN_CONFIDENCE_THRESHOLD → ban

Install:
  pip install "discord.py>=2.3" httpx python-dotenv aiofiles

.env:
  DISCORD_TOKEN=your-bot-token
  MOKOSH_API_URL=https://mokosh-api-9f9713bc633f.herokuapp.com
  MOKOSH_API_TOKEN=          # optional
  DB_PATH=mokosh.db
  LOG_CHANNEL_NAME=mokosh-log  # bot will create it if missing
────────────────────────────────────────────
"""

import io
import json
import sqlite3
import os
import httpx
import discord
from discord import app_commands
from discord.ext import commands
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN    = os.getenv("DISCORD_TOKEN")
API_URL          = os.getenv("MOKOSH_API_URL", "https://mokosh-api-9f9713bc633f.herokuapp.com")
API_TOKEN        = os.getenv("API_TOKEN", "")
DB_PATH          = os.getenv("DB_PATH", "mokosh.db")
LOG_CHANNEL_NAME = os.getenv("LOG_CHANNEL_NAME", "mokosh-log")

# ── Moderation thresholds ──────────────────────
BAN_VIOLATION_THRESHOLD  = 2
BAN_CONFIDENCE_THRESHOLD = 0.80


def api_headers() -> dict:
    return {"X-API-Token": API_TOKEN} if API_TOKEN else {}


# ═══════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                settings TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS violations (
                guild_id INTEGER NOT NULL,
                user_id  INTEGER NOT NULL,
                count    INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (guild_id, user_id)
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


DEFAULT_SETTINGS = {
    "min_confidence_for_action":  0.55,
    "mute_threshold_violations":  2,
    "block_threshold_violations": 4,
    "auto_warn":                  True,
    "auto_block":                 True,
    "instant_mute_categories":    ["sexual", "verbal_abuse", "harassment", "gasslighting"],
    "instant_block_categories":   ["threat", "stalking"],
    "apply_only_if_not_safe":     True,
    "tag_sender_in_reply":        True,
}


def get_settings(guild_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT settings FROM guild_settings WHERE guild_id = ?", (guild_id,)
        ).fetchone()
    return {**DEFAULT_SETTINGS, **json.loads(row["settings"])} if row else dict(DEFAULT_SETTINGS)


def save_settings(guild_id: int, settings: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO guild_settings (guild_id, settings) VALUES (?, ?)
               ON CONFLICT(guild_id) DO UPDATE SET settings = excluded.settings""",
            (guild_id, json.dumps(settings)),
        )


def get_violations(guild_id: int, user_id: int) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT count FROM violations WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ).fetchone()
    return row["count"] if row else 0


def set_violations(guild_id: int, user_id: int, count: int):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO violations (guild_id, user_id, count) VALUES (?, ?, ?)
               ON CONFLICT(guild_id, user_id) DO UPDATE SET count = excluded.count""",
            (guild_id, user_id, count),
        )


# ═══════════════════════════════════════════════
# API CALLERS
# ═══════════════════════════════════════════════

async def api_text(text: str, sender_id: str, sender_display: str, prior: int, settings: dict) -> dict | None:
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(
                f"{API_URL}/analyze/messages",
                headers=api_headers(),
                json={
                    "messages": [{
                        "sender_id":        sender_id,
                        "sender_display":   sender_display,
                        "text":             text,
                        "prior_violations": prior,
                    }],
                    "settings": settings,
                },
                timeout=20.0,
            )
            data = r.json()
            print(f"[DEBUG] /analyze/messages → {r.status_code} {data}")
            if isinstance(data, dict) and "results" in data:
                return data["results"][0]
            return data
        except Exception as e:
            print(f"[ERROR] /analyze/messages failed: {e}")
            return None


async def api_image(file_bytes: bytes, filename: str, caption: str | None, prior: int, sender_label: str) -> dict | None:
    async with httpx.AsyncClient() as client:
        try:
            data = {"prior_violations": str(prior), "sender_label": sender_label}
            if caption:
                data["caption"] = caption
            r = await client.post(
                f"{API_URL}/analyze/image",
                headers=api_headers(),
                data=data,
                files={"file": (filename, file_bytes, "image/jpeg")},
                timeout=30.0,
            )
            return r.json()
        except Exception as e:
            print(f"[ERROR] /analyze/image failed: {e}")
            return None


async def api_audio(file_bytes: bytes, filename: str, prior: int, sender_label: str) -> dict | None:
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(
                f"{API_URL}/analyze/audio",
                headers=api_headers(),
                data={"prior_violations": str(prior), "sender_label": sender_label},
                files={"file": (filename, file_bytes, "audio/ogg")},
                timeout=40.0,
            )
            return r.json()
        except Exception as e:
            print(f"[ERROR] /analyze/audio failed: {e}")
            return None


async def api_video(file_bytes: bytes, filename: str, caption: str | None, prior: int, sender_label: str) -> dict | None:
    async with httpx.AsyncClient() as client:
        try:
            data = {"prior_violations": str(prior), "sender_label": sender_label}
            if caption:
                data["caption"] = caption
            r = await client.post(
                f"{API_URL}/analyze/video",
                headers=api_headers(),
                data=data,
                files={"file": (filename, file_bytes, "video/mp4")},
                timeout=60.0,
            )
            return r.json()
        except Exception as e:
            print(f"[ERROR] /analyze/video failed: {e}")
            return None


def is_bad_result(result: dict) -> bool:
    return bool(result.get("is_bad") or result.get("status") == "bad")


# ═══════════════════════════════════════════════
# BOT SETUP
# ═══════════════════════════════════════════════

intents = discord.Intents.default()
intents.message_content = True
intents.members         = True

bot = commands.Bot(command_prefix="!", intents=intents)


# ─── Log channel helper ──────────────────────────

async def get_log_channel(guild: discord.Guild) -> discord.TextChannel | None:
    """Return existing log channel or create it if missing."""
    existing = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
    if existing:
        return existing
    try:
        # Create private channel visible only to admins + bot
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me:           discord.PermissionOverwrite(read_messages=True, send_messages=True),
        }
        for role in guild.roles:
            if role.permissions.administrator:
                overwrites[role] = discord.PermissionOverwrite(read_messages=True)
        return await guild.create_text_channel(LOG_CHANNEL_NAME, overwrites=overwrites)
    except Exception as e:
        print(f"[WARN] Could not create log channel: {e}")
        return None


# ─── Embed builders ─────────────────────────────

def warn_embed(
    member: discord.Member,
    categories: str,
    confidence: float,
    violation_count: int,
    media_label: str,
    api_verdict: str,
) -> discord.Embed:
    embed = discord.Embed(
        title="⚠️ Violation Detected",
        color=discord.Color.orange(),
    )
    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
    if media_label:
        embed.add_field(name="Content type", value=media_label, inline=True)
    embed.add_field(name="Category",    value=f"`{categories}`",           inline=True)
    embed.add_field(name="Confidence",  value=f"`{confidence:.0%}`",       inline=True)
    embed.add_field(name="Violations",  value=f"`{violation_count}` total", inline=True)
    if api_verdict:
        embed.add_field(name="AI note", value=api_verdict[:500], inline=False)
    embed.set_footer(text=f"Ban triggers at {BAN_VIOLATION_THRESHOLD}+ violations with {int(BAN_CONFIDENCE_THRESHOLD*100)}%+ confidence")
    return embed


def ban_embed(member: discord.Member, confidence: float, violation_count: int) -> discord.Embed:
    embed = discord.Embed(
        title="🚫 User Banned",
        description=f"{member.mention} has been permanently banned.",
        color=discord.Color.red(),
    )
    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
    embed.add_field(name="Violations", value=str(violation_count), inline=True)
    embed.add_field(name="Confidence", value=f"{confidence:.0%}",  inline=True)
    return embed


# ─── Core verdict handler ────────────────────────

async def apply_verdict(
    message: discord.Message,
    result: dict,
    media_label: str = "",
) -> None:
    guild  = message.guild
    member = message.author
    if not guild or not isinstance(member, discord.Member):
        return

    guild_id = guild.id
    user_id  = member.id

    categories  = result.get("category", [])
    if isinstance(categories, list):
        categories = ", ".join(categories)
    confidence  = result.get("confidence", 0.0)
    api_verdict = result.get("sender_response") or result.get("response", "")

    # Increment violation count
    prior     = get_violations(guild_id, user_id)
    new_count = prior + 1
    set_violations(guild_id, user_id, new_count)

    should_ban = (new_count >= BAN_VIOLATION_THRESHOLD and confidence >= BAN_CONFIDENCE_THRESHOLD)

    print(f"[MODERATION] {member} | violations={new_count} conf={confidence:.0%} | ban={should_ban}")

    # 1. Always delete the message
    try:
        await message.delete()
    except Exception as e:
        print(f"[WARN] Could not delete message: {e}")

    # 2. Post warning as reply (in original channel)
    warn_e = warn_embed(member, categories, confidence, new_count, media_label, api_verdict)
    if should_ban:
        warn_e.color = discord.Color.red()
        warn_e.title = "🚫 Final Violation — User Will Be Banned"

    try:
        await message.channel.send(
            content=f"{member.mention}" + (" — **you have been banned.**" if should_ban else ""),
            embed=warn_e,
        )
    except Exception as e:
        print(f"[WARN] Could not send channel warning: {e}")

    # 3. Post to log channel
    log_ch = await get_log_channel(guild)
    if log_ch:
        log_embed = discord.Embed(
            title="🚫 Ban" if should_ban else "⚠️ Warn",
            color=discord.Color.red() if should_ban else discord.Color.orange(),
        )
        log_embed.set_author(name=str(member), icon_url=member.display_avatar.url)
        log_embed.add_field(name="User",      value=f"{member.mention} (`{member.id}`)", inline=False)
        log_embed.add_field(name="Channel",   value=message.channel.mention,             inline=True)
        log_embed.add_field(name="Category",  value=f"`{categories}`",                   inline=True)
        log_embed.add_field(name="Confidence",value=f"`{confidence:.0%}`",               inline=True)
        log_embed.add_field(name="Violations",value=str(new_count),                      inline=True)
        if media_label:
            log_embed.add_field(name="Media", value=media_label, inline=True)
        if api_verdict:
            log_embed.add_field(name="AI note", value=api_verdict[:500], inline=False)
        try:
            await log_ch.send(embed=log_embed)
        except Exception as e:
            print(f"[WARN] Could not post to log channel: {e}")

    # 4. Ban if threshold reached
    if should_ban:
        try:
            await guild.ban(member, reason=f"Mokosh: {new_count} violations, {confidence:.0%} confidence")
            print(f"[BAN] {member} ({user_id}) banned from {guild.name}")
        except Exception as e:
            print(f"[WARN] Ban failed: {e}")


# ═══════════════════════════════════════════════
# EVENT: MESSAGE
# ═══════════════════════════════════════════════

@bot.event
async def on_message(message: discord.Message):
    # Ignore DMs, bots, and system messages
    if not message.guild or message.author.bot or not message.author:
        return

    await bot.process_commands(message)  # allow prefix commands to still work

    guild_id       = message.guild.id
    sender_id      = str(message.author.id)
    sender_display = message.author.display_name
    prior          = get_violations(guild_id, message.author.id)
    settings       = get_settings(guild_id)

    # ── Text ─────────────────────────────────────
    if message.content.strip():
        result = await api_text(message.content, sender_id, sender_display, prior, settings)
        if result and is_bad_result(result):
            await apply_verdict(message, result)
            return  # stop processing attachments if text itself is already bad

    # ── Attachments ──────────────────────────────
    for attachment in message.attachments:
        name = attachment.filename.lower()
        ct   = (attachment.content_type or "").lower()

        try:
            file_bytes = await attachment.read()
        except Exception as e:
            print(f"[ERROR] Could not read attachment {name}: {e}")
            continue

        result = None

        # Image
        if ct.startswith("image/") or name.endswith((".jpg", ".jpeg", ".png", ".webp", ".gif")):
            result = await api_image(file_bytes, attachment.filename, message.content or None, prior, sender_display)
            label  = "🖼 Image"

        # Audio
        elif ct.startswith("audio/") or name.endswith((".ogg", ".mp3", ".wav", ".m4a", ".opus")):
            result = await api_audio(file_bytes, attachment.filename, prior, sender_display)
            label  = "🎙 Audio"

        # Video
        elif ct.startswith("video/") or name.endswith((".mp4", ".mov", ".webm", ".mkv")):
            if attachment.size > 20 * 1024 * 1024:
                print(f"[SKIP] Video too large: {attachment.size} bytes")
                continue
            result = await api_video(file_bytes, attachment.filename, message.content or None, prior, sender_display)
            label  = "🎥 Video"

        else:
            continue

        if result and is_bad_result(result):
            await apply_verdict(message, result, media_label=label)
            break  # one verdict per message is enough


# ═══════════════════════════════════════════════
# SLASH COMMANDS
# ═══════════════════════════════════════════════

@bot.tree.command(name="check", description="Analyze text for harassment (no moderation applied)")
@app_commands.describe(text="The message text to analyze")
async def slash_check(interaction: discord.Interaction, text: str):
    await interaction.response.defer(ephemeral=True)

    guild_id = interaction.guild_id
    settings = get_settings(guild_id) if guild_id else dict(DEFAULT_SETTINGS)

    result = await api_text(text, "check_user", "checked text", 0, settings)
    if result is None:
        await interaction.followup.send("❌ API error — could not analyze.", ephemeral=True)
        return

    is_bad     = result.get("is_bad", False)
    categories = ", ".join(result.get("category", []))
    confidence = result.get("confidence", 0.0)
    action     = result.get("action", "none")
    explanation= result.get("explanation", "")

    embed = discord.Embed(
        title=f"{'🔴 HARMFUL' if is_bad else '🟢 SAFE'}",
        color=discord.Color.red() if is_bad else discord.Color.green(),
    )
    embed.add_field(name="Category",         value=f"`{categories or 'safe'}`", inline=True)
    embed.add_field(name="Confidence",       value=f"`{confidence:.0%}`",       inline=True)
    embed.add_field(name="Suggested action", value=f"`{action}`",               inline=True)
    if explanation:
        embed.add_field(name="Analysis", value=explanation[:1000], inline=False)

    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="violations", description="Show a user's violation count (admins only)")
@app_commands.describe(user="The user to look up")
@app_commands.default_permissions(administrator=True)
async def slash_violations(interaction: discord.Interaction, user: discord.Member):
    count = get_violations(interaction.guild_id, user.id)
    embed = discord.Embed(
        title="📊 Violation Record",
        color=discord.Color.blurple(),
    )
    embed.set_author(name=str(user), icon_url=user.display_avatar.url)
    embed.add_field(name="Violations", value=str(count), inline=True)
    embed.add_field(
        name="Status",
        value="⚠️ One more triggers ban" if count == BAN_VIOLATION_THRESHOLD - 1 else (
              "🚫 Will be banned on next violation" if count >= BAN_VIOLATION_THRESHOLD else "✅ Clean"
        ),
        inline=True,
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="reset", description="Reset a user's violation count (admins only)")
@app_commands.describe(user="The user to reset")
@app_commands.default_permissions(administrator=True)
async def slash_reset(interaction: discord.Interaction, user: discord.Member):
    set_violations(interaction.guild_id, user.id, 0)
    await interaction.response.send_message(
        f"✅ Violation count for {user.mention} has been reset to 0.",
        ephemeral=True,
    )


@bot.tree.command(name="settings", description="View or change Mokosh moderation settings (admins only)")
@app_commands.default_permissions(administrator=True)
async def slash_settings(interaction: discord.Interaction):
    await interaction.response.send_message(
        embed=settings_embed(interaction.guild_id),
        view=SettingsView(interaction.guild_id),
        ephemeral=True,
    )


# ═══════════════════════════════════════════════
# SETTINGS UI (discord.ui Views & Selects)
# ═══════════════════════════════════════════════

ALL_CATEGORIES = ["sexual", "verbal_abuse", "harassment", "gasslighting", "threat", "stalking", "other"]


def settings_embed(guild_id: int) -> discord.Embed:
    s  = get_settings(guild_id)
    aw = "✅" if s["auto_warn"]  else "❌"
    ab = "✅" if s["auto_block"] else "❌"
    imute  = ", ".join(s["instant_mute_categories"])  or "none"
    iblock = ", ".join(s["instant_block_categories"]) or "none"

    embed = discord.Embed(title="⚙️ Mokosh Settings", color=discord.Color.blurple())
    embed.add_field(name="🎯 Confidence threshold", value=f"`{s['min_confidence_for_action']}`",  inline=True)
    embed.add_field(name="📈 Mute after N violations", value=f"`{s['mute_threshold_violations']}`", inline=True)
    embed.add_field(name="🚫 Ban after N violations",  value=f"`{s['block_threshold_violations']}`",inline=True)
    embed.add_field(name="⚠️ Auto-warn",  value=aw, inline=True)
    embed.add_field(name="🚫 Auto-ban",   value=ab, inline=True)
    embed.add_field(name="⚡ Instant mute categories", value=f"`{imute}`",  inline=False)
    embed.add_field(name="💥 Instant ban categories",  value=f"`{iblock}`", inline=False)
    embed.set_footer(text="Use the buttons below to change settings.")
    return embed


class SettingsView(discord.ui.View):
    def __init__(self, guild_id: int):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        self.add_item(ConfidenceSelect(guild_id))
        self.add_item(MuteThreshSelect(guild_id))
        self.add_item(BanThreshSelect(guild_id))

    @discord.ui.button(label="Toggle Auto-warn", style=discord.ButtonStyle.secondary, row=3)
    async def toggle_warn(self, interaction: discord.Interaction, button: discord.ui.Button):
        s = get_settings(self.guild_id)
        s["auto_warn"] = not s["auto_warn"]
        save_settings(self.guild_id, s)
        await interaction.response.edit_message(embed=settings_embed(self.guild_id), view=self)

    @discord.ui.button(label="Toggle Auto-ban", style=discord.ButtonStyle.secondary, row=3)
    async def toggle_ban(self, interaction: discord.Interaction, button: discord.ui.Button):
        s = get_settings(self.guild_id)
        s["auto_block"] = not s["auto_block"]
        save_settings(self.guild_id, s)
        await interaction.response.edit_message(embed=settings_embed(self.guild_id), view=self)

    @discord.ui.button(label="⚡ Instant mute cats", style=discord.ButtonStyle.primary, row=4)
    async def instant_mute_cats(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            "Select categories for **instant mute**:",
            view=CategoryToggleView(self.guild_id, "instant_mute_categories"),
            ephemeral=True,
        )

    @discord.ui.button(label="💥 Instant ban cats", style=discord.ButtonStyle.danger, row=4)
    async def instant_ban_cats(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            "Select categories for **instant ban**:",
            view=CategoryToggleView(self.guild_id, "instant_block_categories"),
            ephemeral=True,
        )


class ConfidenceSelect(discord.ui.Select):
    def __init__(self, guild_id: int):
        self.guild_id = guild_id
        options = [
            discord.SelectOption(label=f"Confidence threshold: {v}", value=str(v))
            for v in [0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]
        ]
        super().__init__(placeholder="🎯 Set confidence threshold", options=options, row=0)

    async def callback(self, interaction: discord.Interaction):
        s = get_settings(self.guild_id)
        s["min_confidence_for_action"] = float(self.values[0])
        save_settings(self.guild_id, s)
        await interaction.response.edit_message(embed=settings_embed(self.guild_id), view=self.view)


class MuteThreshSelect(discord.ui.Select):
    def __init__(self, guild_id: int):
        self.guild_id = guild_id
        options = [
            discord.SelectOption(label=f"Mute after {v} violations", value=str(v))
            for v in range(1, 11)
        ]
        super().__init__(placeholder="📈 Mute threshold", options=options, row=1)

    async def callback(self, interaction: discord.Interaction):
        s = get_settings(self.guild_id)
        s["mute_threshold_violations"] = int(self.values[0])
        save_settings(self.guild_id, s)
        await interaction.response.edit_message(embed=settings_embed(self.guild_id), view=self.view)


class BanThreshSelect(discord.ui.Select):
    def __init__(self, guild_id: int):
        self.guild_id = guild_id
        options = [
            discord.SelectOption(label=f"Ban after {v} violations", value=str(v))
            for v in range(1, 11)
        ]
        super().__init__(placeholder="🚫 Ban threshold", options=options, row=2)

    async def callback(self, interaction: discord.Interaction):
        s = get_settings(self.guild_id)
        s["block_threshold_violations"] = int(self.values[0])
        save_settings(self.guild_id, s)
        await interaction.response.edit_message(embed=settings_embed(self.guild_id), view=self.view)


class CategoryToggleView(discord.ui.View):
    def __init__(self, guild_id: int, key: str):
        super().__init__(timeout=120)
        self.add_item(CategorySelect(guild_id, key))


class CategorySelect(discord.ui.Select):
    def __init__(self, guild_id: int, key: str):
        self.guild_id = guild_id
        self.key      = key
        current = get_settings(guild_id)[key]
        options = [
            discord.SelectOption(label=cat, value=cat, default=(cat in current))
            for cat in ALL_CATEGORIES
        ]
        super().__init__(
            placeholder="Select categories (toggle)",
            options=options,
            min_values=0,
            max_values=len(ALL_CATEGORIES),
        )

    async def callback(self, interaction: discord.Interaction):
        s = get_settings(self.guild_id)
        s[self.key] = self.values
        save_settings(self.guild_id, s)
        await interaction.response.send_message(
            f"✅ `{self.key}` updated: `{', '.join(self.values) or 'none'}`",
            ephemeral=True,
        )


# ═══════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════

@bot.event
async def on_ready():
    init_db()
    await bot.tree.sync()
    print(f"✅ Mokosh is online as {bot.user} — slash commands synced")
    print(f"   Monitoring {len(bot.guilds)} server(s)")
    print(f"   Ban threshold: {BAN_VIOLATION_THRESHOLD} violations + {int(BAN_CONFIDENCE_THRESHOLD*100)}% confidence")


@bot.event
async def on_guild_join(guild: discord.Guild):
    print(f"[JOIN] Added to: {guild.name} ({guild.id})")
    await get_log_channel(guild)   # pre-create the log channel
    system = guild.system_channel
    if system:
        embed = discord.Embed(
            title="👋 Mokosh is here!",
            description=(
                "I'm an AI-powered harassment detection bot.\n\n"
                "I monitor all messages — text, images, audio, and video.\n\n"
                "**What I do on violations:**\n"
                "⚠️ Warn the sender (delete message)\n"
                "🚫 Ban after repeated violations\n\n"
                "**Commands:**\n"
                "`/check` — analyze any text\n"
                "`/settings` — configure moderation (admins)\n"
                "`/violations` — check a user's record (admins)\n"
                "`/reset` — clear a user's violations (admins)\n\n"
                f"A private `#{LOG_CHANNEL_NAME}` channel has been created for admin logs.\n\n"
                "⚙️ Make sure I have **Ban Members**, **Manage Messages**, and **Read Message History** permissions."
            ),
            color=discord.Color.blurple(),
        )
        try:
            await system.send(embed=embed)
        except Exception:
            pass


if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)