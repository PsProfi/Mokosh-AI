"""
Mokosh Telegram Bot
────────────────────────────────────────────
API: https://mokosh-api-9f9713bc633f.herokuapp.com
Endpoints used:
  POST /analyze/messages  — text moderation
  POST /analyze/image     — multipart image upload
  POST /analyze/audio     — multipart audio upload
  POST /analyze/video     — multipart video upload

Commands:
  /start    — welcome + add to group button (private)
  /check    — analyze text for harassment (group + private)
  /settings — interactive settings panel (group admins only)
────────────────────────────────────────────
Storage: SQLite (mokosh.db)
  • per-chat moderation settings
  • per-chat per-user violation counts
"""

import io
import json
import sqlite3
import httpx
import os
from contextlib import contextmanager

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    CommandHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API_URL        = os.getenv("HARASSMENT_API_URL", "https://mokosh-api-9f9713bc633f.herokuapp.com")
BOT_USERNAME   = os.getenv("BOT_USERNAME", "your_bot")
API_TOKEN      = os.getenv("API_TOKEN")       # optional X-API-Token header
DB_PATH        = os.getenv("DB_PATH", "mokosh.db")


def api_headers() -> dict:
    h = {}
    if API_TOKEN:
        h["X-API-Token"] = API_TOKEN
    return h


# ═══════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id  INTEGER PRIMARY KEY,
                settings TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS violations (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                count   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (chat_id, user_id)
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
    "mute_minutes":               60,
    "mute_threshold_violations":  2,
    "block_threshold_violations": 4,
    "auto_warn":                  True,
    "auto_mute":                  True,
    "auto_block":                 True,
    "instant_mute_categories":    ["sexual", "verbal_abuse", "harassment", "gasslighting"],
    "instant_block_categories":   ["threat", "stalking"],
    "apply_only_if_not_safe":     True,
    "tag_sender_in_reply":        True,
}


def get_settings(chat_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT settings FROM chat_settings WHERE chat_id = ?", (chat_id,)
        ).fetchone()
    if row:
        return {**DEFAULT_SETTINGS, **json.loads(row["settings"])}
    return dict(DEFAULT_SETTINGS)


def save_settings(chat_id: int, settings: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO chat_settings (chat_id, settings) VALUES (?, ?)
               ON CONFLICT(chat_id) DO UPDATE SET settings = excluded.settings""",
            (chat_id, json.dumps(settings)),
        )


def get_violations(chat_id: int, user_id: int) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT count FROM violations WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        ).fetchone()
    return row["count"] if row else 0


def set_violations(chat_id: int, user_id: int, count: int):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO violations (chat_id, user_id, count) VALUES (?, ?, ?)
               ON CONFLICT(chat_id, user_id) DO UPDATE SET count = excluded.count""",
            (chat_id, user_id, count),
        )


# ═══════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════

def esc(text: str) -> str:
    """Escape text for Telegram MarkdownV2."""
    for ch in r"\_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        member = await context.bot.get_chat_member(
            update.effective_chat.id, update.effective_user.id
        )
        return member.status in ("administrator", "creator")
    except Exception:
        return False


async def download_file(bot, file_id: str) -> bytes:
    tg_file = await bot.get_file(file_id)
    buf = io.BytesIO()
    await tg_file.download_to_memory(buf)
    return buf.getvalue()


def is_bad_result(result: dict) -> bool:
    """Works for both /analyze/messages result and raw /analyze/image|audio|video result."""
    return bool(result.get("is_bad") or result.get("status") == "bad")


# ─── API callers ────────────────────────────────

async def api_text(
    text: str,
    sender_id: str,
    sender_display: str,
    prior: int,
    settings: dict,
) -> dict | None:
    """POST /analyze/messages"""
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
            print(f"[DEBUG] /analyze/messages raw: {r.status_code} {data}")
            # Handle both {"results": [...]} and direct object
            if isinstance(data, dict) and "results" in data:
                return data["results"][0]
            return data
        except Exception as e:
            print(f"[ERROR] /analyze/messages failed: {e}")
            return None


async def api_image(
    file_bytes: bytes,
    filename: str,
    caption: str | None,
    prior: int,
    sender_label: str,
) -> dict | None:
    """POST /analyze/image  (multipart)"""
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


async def api_audio(
    file_bytes: bytes,
    filename: str,
    prior: int,
    sender_label: str,
) -> dict | None:
    """POST /analyze/audio  (multipart)"""
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


async def api_video(
    file_bytes: bytes,
    filename: str,
    caption: str | None,
    prior: int,
    sender_label: str,
) -> dict | None:
    """POST /analyze/video  (multipart)"""
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


# ─── Verdict renderer & enforcer ────────────────
#
# Custom moderation logic (API action field is ignored):
#   • Every harmful detection  → warn in chat + increment violation count
#   • violations >= 2 AND confidence >= 0.80 → ban immediately
#
BAN_VIOLATION_THRESHOLD = 2
BAN_CONFIDENCE_THRESHOLD = 0.80


async def apply_verdict(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    result: dict,
    chat_id: int,
    sender_id: int,
    media_label: str = "",
) -> None:
    message        = update.message
    sender_display = message.from_user.username or message.from_user.first_name

    categories = result.get("category", [])
    if isinstance(categories, list):
        categories = ", ".join(categories)
    confidence  = result.get("confidence", 0.0)
    api_verdict = result.get("sender_response") or result.get("response", "")
    label_line  = f"Content: `{esc(media_label)}`\n" if media_label else ""

    # Read current violations BEFORE incrementing
    prior = get_violations(chat_id, sender_id)
    new_count = prior + 1
    set_violations(chat_id, sender_id, new_count)

    # Decide action purely on our own rules
    should_ban = (new_count >= BAN_VIOLATION_THRESHOLD and confidence >= BAN_CONFIDENCE_THRESHOLD)

    if should_ban:
        action_emoji = "🚫"
        action_text  = "banned"
        action_note  = (
            f"🚫 *@{esc(sender_display)} has been banned*\n"
            f"Reason: {new_count} violations, confidence {confidence:.0%}"
        )
    else:
        action_emoji = "⚠️"
        action_text  = "warned"
        action_note  = (
            f"⚠️ @{esc(sender_display)}, "
            f"{esc(api_verdict) if api_verdict else 'please do not write like this.'}\n\n"
            f"_Violation {new_count} recorded\\. "
            f"Ban triggers at {BAN_VIOLATION_THRESHOLD}\\+ violations with {int(BAN_CONFIDENCE_THRESHOLD*100)}\\%\\+ confidence\\._"
        )

    print(f"[MODERATION] {sender_display} | violations={new_count} conf={confidence:.0%} → {action_text}")

    try:
        await message.reply_text(
            f"{action_emoji} *Violation detected*\n"
            f"{label_line}"
            f"Category: `{esc(categories)}`\n"
            f"Confidence: `{confidence:.0%}`\n\n"
            f"{action_note}",
            parse_mode="MarkdownV2",
        )
    except Exception as e:
        print(f"[ERROR] reply_text failed: {e}")
        return

    if should_ban:
        try:
            await message.delete()
        except Exception as e:
            print(f"[WARN] delete failed: {e}")
        try:
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=sender_id)
            print(f"[BAN] {sender_display} ({sender_id}) banned from {chat_id}")
        except Exception as e:
            print(f"[WARN] ban failed: {e}")


# ═══════════════════════════════════════════════
# SETTINGS PANEL
# ═══════════════════════════════════════════════

ALL_CATEGORIES = ["sexual", "verbal_abuse", "harassment", "gasslighting", "threat", "stalking", "other"]


def settings_menu(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    s  = get_settings(chat_id)
    aw = "✅" if s["auto_warn"]  else "❌"
    am = "✅" if s["auto_mute"]  else "❌"
    ab = "✅" if s["auto_block"] else "❌"
    imute  = esc(", ".join(s["instant_mute_categories"])  or "none")
    iblock = esc(", ".join(s["instant_block_categories"]) or "none")

    text = (
        "⚙️ *Mokosh Settings*\n\n"
        f"🎯 Confidence threshold: `{s['min_confidence_for_action']}`\n"
        f"⏱ Mute duration: `{s['mute_minutes']} min`\n"
        f"📈 Mute after violations: `{s['mute_threshold_violations']}`\n"
        f"🚫 Ban after violations: `{s['block_threshold_violations']}`\n"
        f"⚠️ Auto\\-warn: {aw}\n"
        f"🔇 Auto\\-mute: {am}\n"
        f"🚫 Auto\\-ban: {ab}\n"
        f"⚡ Instant mute: `{imute}`\n"
        f"💥 Instant ban: `{iblock}`"
    )
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"⚠️ Auto-warn {aw}",  callback_data=f"stg|{chat_id}|toggle|auto_warn"),
            InlineKeyboardButton(f"🔇 Auto-mute {am}",  callback_data=f"stg|{chat_id}|toggle|auto_mute"),
            InlineKeyboardButton(f"🚫 Auto-ban {ab}",   callback_data=f"stg|{chat_id}|toggle|auto_block"),
        ],
        [
            InlineKeyboardButton("🎯 −",  callback_data=f"stg|{chat_id}|conf|-"),
            InlineKeyboardButton(f"Conf {s['min_confidence_for_action']}", callback_data="noop"),
            InlineKeyboardButton("🎯 +",  callback_data=f"stg|{chat_id}|conf|+"),
        ],
        [
            InlineKeyboardButton("⏱ −15m", callback_data=f"stg|{chat_id}|mute|-"),
            InlineKeyboardButton(f"Mute {s['mute_minutes']}m", callback_data="noop"),
            InlineKeyboardButton("⏱ +15m", callback_data=f"stg|{chat_id}|mute|+"),
        ],
        [
            InlineKeyboardButton("📈 Mute thresh −", callback_data=f"stg|{chat_id}|muteth|-"),
            InlineKeyboardButton(f"mute@{s['mute_threshold_violations']}", callback_data="noop"),
            InlineKeyboardButton("📈 Mute thresh +", callback_data=f"stg|{chat_id}|muteth|+"),
        ],
        [
            InlineKeyboardButton("📈 Ban thresh −",  callback_data=f"stg|{chat_id}|banth|-"),
            InlineKeyboardButton(f"ban@{s['block_threshold_violations']}", callback_data="noop"),
            InlineKeyboardButton("📈 Ban thresh +",  callback_data=f"stg|{chat_id}|banth|+"),
        ],
        [
            InlineKeyboardButton("⚡ Instant mute cats",  callback_data=f"stg|{chat_id}|cats|mute"),
            InlineKeyboardButton("💥 Instant ban cats",   callback_data=f"stg|{chat_id}|cats|block"),
        ],
        [InlineKeyboardButton("✅ Done", callback_data=f"stg|{chat_id}|close|")],
    ])
    return text, keyboard


def category_menu(chat_id: int, cat_type: str) -> tuple[str, InlineKeyboardMarkup]:
    s   = get_settings(chat_id)
    key = "instant_mute_categories" if cat_type == "mute" else "instant_block_categories"
    current = s[key]
    label   = "Instant Mute" if cat_type == "mute" else "Instant Ban"
    rows = [
        [InlineKeyboardButton(
            f"{'✅' if c in current else '☐'} {c}",
            callback_data=f"stg|{chat_id}|cattoggle|{cat_type}:{c}"
        )]
        for c in ALL_CATEGORIES
    ]
    rows.append([InlineKeyboardButton("← Back", callback_data=f"stg|{chat_id}|back|")])
    return f"⚡ *{esc(label)} Categories*\nTap to toggle:", InlineKeyboardMarkup(rows)


# ═══════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user       = update.effective_user
    first_name = esc(user.first_name if user else "there")
    url        = f"https://t.me/{BOT_USERNAME}?startgroup=true"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add me to a group", url=url)],
        [InlineKeyboardButton("📖 How it works", callback_data="how_it_works")],
    ])
    await update.message.reply_text(
        f"👋 Hi, {first_name}\\!\n\n"
        "I'm *Mokosh* — an AI\\-powered harassment detection bot\\.\n\n"
        "I monitor group chats and detect harmful messages automatically\\.\n\n"
        "*What I can analyze:*\n"
        "💬 Text messages\n"
        "🖼 Photos \\& GIFs\n"
        "🎙 Voice messages\n"
        "🎥 Videos\n\n"
        "*What I do when I find something bad:*\n"
        "⚠️ Warn the sender\n"
        "🔇 Mute repeat offenders\n"
        "🚫 Ban users with severe violations\n\n"
        "*Commands:*\n"
        "`/check <text>` — analyze any text\n"
        "`/settings` — configure moderation \\(admins\\)\n\n"
        "Add me to your group using the button below 👇",
        parse_mode="MarkdownV2",
        reply_markup=keyboard,
    )


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/check <text> — analyze text, no moderation applied."""
    message       = update.message
    text_to_check = " ".join(context.args).strip() if context.args else ""

    if not text_to_check:
        await message.reply_text(
            "Usage: `/check <message text>`\n\nExample: `/check I will find you`",
            parse_mode="MarkdownV2",
        )
        return

    is_group = message.chat.type in ("group", "supergroup")
    settings = get_settings(message.chat_id) if is_group else dict(DEFAULT_SETTINGS)

    await message.reply_text("🔍 Analyzing\\.\\.\\.", parse_mode="MarkdownV2")

    result = await api_text(
        text=text_to_check,
        sender_id="check_user",
        sender_display="checked text",
        prior=0,
        settings=settings,
    )

    if result is None:
        await message.reply_text("❌ API error — could not analyze\\.", parse_mode="MarkdownV2")
        return

    is_bad      = result["is_bad"]
    categories  = ", ".join(result.get("category", []))
    confidence  = result.get("confidence", 0.0)
    action      = result.get("action", "none")
    explanation = result.get("explanation", "")
    icon   = "🔴" if is_bad else "🟢"
    status = "HARMFUL" if is_bad else "SAFE"

    await message.reply_text(
        f"{icon} *Result: {esc(status)}*\n\n"
        f"Category: `{esc(categories)}`\n"
        f"Confidence: `{confidence:.0%}`\n"
        f"Suggested action: `{esc(action)}`\n\n"
        f"*Analysis:*\n{esc(explanation)}",
        parse_mode="MarkdownV2",
    )


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if update.effective_chat.type not in ("group", "supergroup"):
        await message.reply_text("⚙️ `/settings` can only be used inside a group chat\\.", parse_mode="MarkdownV2")
        return
    if not await is_admin(update, context):
        await message.reply_text("🔒 Only group admins can change settings\\.", parse_mode="MarkdownV2")
        return
    text, keyboard = settings_menu(update.effective_chat.id)
    await message.reply_text(text, parse_mode="MarkdownV2", reply_markup=keyboard)


# ═══════════════════════════════════════════════
# SETTINGS CALLBACK
# ═══════════════════════════════════════════════

async def settings_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "noop":
        return

    if data == "how_it_works":
        await query.message.reply_text(
            "🤖 *How Mokosh works:*\n\n"
            "1\\. Add me to your group as *admin*\n"
            "   _\\(Delete messages, Ban users, Restrict members\\)_\n\n"
            "2\\. I silently watch every message\n\n"
            "3\\. I analyze *text*, *photos*, *voice*, *GIFs* and *video* via the Mokosh API\n\n"
            "4\\. On violations: warn → mute → ban\n\n"
            "Use `/check <text>` to manually test any message\\.\n"
            "Use `/settings` \\(admins\\) to customize behavior\\.",
            parse_mode="MarkdownV2",
        )
        return

    if not data.startswith("stg|"):
        return

    _, chat_id_str, action, param = data.split("|", 3)
    chat_id = int(chat_id_str)

    try:
        member = await context.bot.get_chat_member(chat_id, query.from_user.id)
        if member.status not in ("administrator", "creator"):
            await query.answer("🔒 Admins only.", show_alert=True)
            return
    except Exception:
        await query.answer("🔒 Could not verify admin status.", show_alert=True)
        return

    s = get_settings(chat_id)

    if action == "close":
        await query.message.delete()
        return
    elif action == "back":
        text, kb = settings_menu(chat_id)
        await query.message.edit_text(text, parse_mode="MarkdownV2", reply_markup=kb)
        return
    elif action == "toggle":
        s[param] = not s[param]
    elif action == "conf":
        val = round(s["min_confidence_for_action"] + (0.05 if param == "+" else -0.05), 2)
        s["min_confidence_for_action"] = max(0.0, min(1.0, val))
    elif action == "mute":
        val = s["mute_minutes"] + (15 if param == "+" else -15)
        s["mute_minutes"] = max(1, min(10080, val))
    elif action == "muteth":
        val = s["mute_threshold_violations"] + (1 if param == "+" else -1)
        s["mute_threshold_violations"] = max(1, min(100, val))
    elif action == "banth":
        val = s["block_threshold_violations"] + (1 if param == "+" else -1)
        s["block_threshold_violations"] = max(1, min(100, val))
    elif action == "cats":
        save_settings(chat_id, s)
        text, kb = category_menu(chat_id, param)
        await query.message.edit_text(text, parse_mode="MarkdownV2", reply_markup=kb)
        return
    elif action == "cattoggle":
        cat_type, cat_name = param.split(":", 1)
        key  = "instant_mute_categories" if cat_type == "mute" else "instant_block_categories"
        cats = s[key]
        cats.remove(cat_name) if cat_name in cats else cats.append(cat_name)
        s[key] = cats
        save_settings(chat_id, s)
        text, kb = category_menu(chat_id, cat_type)
        await query.message.edit_text(text, parse_mode="MarkdownV2", reply_markup=kb)
        return

    save_settings(chat_id, s)
    text, kb = settings_menu(chat_id)
    await query.message.edit_text(text, parse_mode="MarkdownV2", reply_markup=kb)


# ═══════════════════════════════════════════════
# MESSAGE HANDLERS
# ═══════════════════════════════════════════════

async def on_bot_added(update: Update, context: ContextTypes.DEFAULT_TYPE):
    for member in update.message.new_chat_members:
        if member.id == context.bot.id:
            await update.message.reply_text(
                "👋 Hello everyone\\! I'm *Mokosh*, your AI safety moderator\\.\n\n"
                "I analyze *text*, *photos*, *voice messages*, *GIFs* and *videos* for harmful content\\.\n\n"
                "Admins: use `/settings` to configure moderation\\.\n"
                "Anyone: use `/check <text>` to test a message\\.\n\n"
                "⚠️ *Give me admin rights* \\(delete messages \\+ restrict users\\) to act on violations\\.\n\n"
                "Stay respectful\\! 🛡️",
                parse_mode="MarkdownV2",
            )
            break


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or not message.text:
        return
    if message.chat.type not in ("group", "supergroup"):
        return

    sender_id      = message.from_user.id
    sender_display = message.from_user.username or message.from_user.first_name
    chat_id        = message.chat_id
    prior          = get_violations(chat_id, sender_id)
    settings       = get_settings(chat_id)

    result = await api_text(message.text, str(sender_id), sender_display, prior, settings)
    if result and is_bad_result(result):
        await apply_verdict(update, context, result, chat_id, sender_id)


async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or message.chat.type not in ("group", "supergroup"):
        return

    voice = message.voice or message.audio
    if not voice:
        return

    sender_id      = message.from_user.id
    sender_display = message.from_user.username or message.from_user.first_name
    chat_id        = message.chat_id
    prior          = get_violations(chat_id, sender_id)

    try:
        file_bytes = await download_file(context.bot, voice.file_id)
    except Exception as e:
        print(f"[ERROR] Voice download failed: {e}")
        return

    result = await api_audio(file_bytes, "voice.ogg", prior, sender_display)
    if result and is_bad_result(result):
        await apply_verdict(update, context, result, chat_id, sender_id, media_label="🎙 Voice")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or message.chat.type not in ("group", "supergroup"):
        return

    photo = message.photo[-1] if message.photo else None
    if not photo:
        return

    sender_id      = message.from_user.id
    sender_display = message.from_user.username or message.from_user.first_name
    chat_id        = message.chat_id
    prior          = get_violations(chat_id, sender_id)
    caption        = message.caption or None

    try:
        file_bytes = await download_file(context.bot, photo.file_id)
    except Exception as e:
        print(f"[ERROR] Photo download failed: {e}")
        return

    result = await api_image(file_bytes, "photo.jpg", caption, prior, sender_display)
    if result and is_bad_result(result):
        await apply_verdict(update, context, result, chat_id, sender_id, media_label="🖼 Photo")


async def handle_video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    if not message or message.chat.type not in ("group", "supergroup"):
        return

    video = message.video or message.animation   # animation = GIF
    if not video:
        return

    sender_id      = message.from_user.id
    sender_display = message.from_user.username or message.from_user.first_name
    chat_id        = message.chat_id
    prior          = get_violations(chat_id, sender_id)
    caption        = message.caption or None

    # Telegram bot download limit is 20MB
    if hasattr(video, "file_size") and video.file_size and video.file_size > 20 * 1024 * 1024:
        print(f"[SKIP] File too large: {video.file_size} bytes")
        return

    try:
        file_bytes = await download_file(context.bot, video.file_id)
    except Exception as e:
        print(f"[ERROR] Video download failed: {e}")
        return

    label  = "🎞 GIF" if message.animation else "🎥 Video"
    result = await api_video(file_bytes, "video.mp4", caption, prior, sender_display)
    if result and is_bad_result(result):
        await apply_verdict(update, context, result, chat_id, sender_id, media_label=label)


# ═══════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    init_db()

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("check",    cmd_check))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CallbackQueryHandler(settings_callback))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, on_bot_added))
    app.add_handler(MessageHandler(filters.TEXT   & ~filters.COMMAND,     handle_text))
    app.add_handler(MessageHandler(filters.VOICE  | filters.AUDIO,        handle_voice))
    app.add_handler(MessageHandler(filters.PHOTO,                          handle_photo))
    app.add_handler(MessageHandler(filters.VIDEO  | filters.ANIMATION,    handle_video))

    print("🤖 Mokosh is running — text / voice / photo / video / GIF moderation active...")
    app.run_polling()