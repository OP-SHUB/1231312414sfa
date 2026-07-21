import sys, os, json, threading, time, random, hashlib, string, re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import telebot
from telebot import types
import requests
telebot.apihelper.session = requests.Session()
telebot.apihelper.session.verify = False

_BASEDIR = os.path.dirname(os.path.abspath(__file__))

from config import BOT_TOKEN, ADMIN_IDS, KEYS_FILE, USERS_FILE, DEVICES_FILE
from bruteforce import tcp_kick_account, GLOBAL_SERVERS

_KEYS_PATH = os.path.join(_BASEDIR, KEYS_FILE)
_USERS_PATH = os.path.join(_BASEDIR, USERS_FILE)
_DEVICES_PATH = os.path.join(_BASEDIR, DEVICES_FILE)

bot = telebot.TeleBot(BOT_TOKEN)

data_lock = threading.Lock()
cancel_events = {}
stats = {'total_kicks': 0, 'failed': 0}
device_sessions = {}  # device_id -> {'uid': int, 'cancel': Event, 'threads': list[Thread]}

# --- Data persistence ---

def load_keys():
    keys = {}
    if not os.path.exists(_KEYS_PATH): return keys
    with open(_KEYS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            key = parts[0]
            status = parts[1] if len(parts) > 1 else 'active'
            created_by = parts[2] if len(parts) > 2 else '0'
            expiry_ts = int(parts[3]) if len(parts) > 3 and parts[3] else 0
            keys[key] = {'status': status, 'created_by': int(created_by), 'expiry_ts': expiry_ts}
    return keys

def save_keys(keys):
    with open(_KEYS_PATH, 'w') as f:
        for k, v in keys.items():
            f.write(f"{k}:{v['status']}:{v['created_by']}:{v.get('expiry_ts', 0)}\n")

def load_users():
    users = {}
    if not os.path.exists(_USERS_PATH): return users
    with open(_USERS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            uid = int(parts[0])
            name = parts[1] if len(parts) > 1 else ''
            key = parts[2] if len(parts) > 2 else ''
            users[uid] = {'name': name, 'key': key}
    return users

def save_users(users):
    with open(_USERS_PATH, 'w') as f:
        for uid, v in users.items():
            f.write(f"{uid}:{v.get('name', '')}:{v.get('key', '')}\n")

def gen_key(length=16):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))

def load_devices():
    devs = {}
    if not os.path.exists(_DEVICES_PATH): return devs
    with open(_DEVICES_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(':', 2)
            uid = int(parts[0])
            name = parts[1] if len(parts) > 1 else ''
            device_id = parts[2] if len(parts) > 2 else ''
            devs[uid] = {'name': name, 'device_id': device_id}
    return devs

def save_devices(devs):
    with open(_DEVICES_PATH, 'w') as f:
        for uid, v in devs.items():
            f.write(f"{uid}:{v.get('name', '')}:{v.get('device_id', '')}\n")

def is_valid_device_id(device_id):
    if not device_id: return False
    if device_id.startswith('ios_'):
        rest = device_id[4:]
        return bool(re.match(r'^[a-fA-F0-9\-]{36}$', rest))
    if device_id.startswith('and_'):
        rest = device_id[4:]
        return len(rest) > 0 and '_' in rest
    return False

def is_admin(user_id):
    return user_id in ADMIN_IDS

def is_authorized(user_id):
    if is_admin(user_id): return True
    users = load_users()
    if user_id not in users: return False
    key = users[user_id].get('key', '')
    if not key: return False
    keys = load_keys()
    info = keys.get(key, {})
    if info.get('status') == 'revoked': return False
    expiry = info.get('expiry_ts', 0)
    if expiry > 0 and time.time() > expiry: return False
    return True

# --- Bot commands ---

@bot.message_handler(commands=['start'])
def cmd_start(message):
    uid = message.from_user.id
    if is_authorized(uid):
        bot.reply_to(message,
            "Welcome back!\n\n"
            "/deviceid <id> — bind your device\n"
            "/on — start bruteforce on binded device\n"
            "/off — stop bruteforce\n"
            "/unbind_deviceid — unbind device\n"
            "/status — current status")
    else:
        bot.reply_to(message,
            "Purchase licence key!\n"
            "Contact: @Shennxs")

@bot.message_handler(commands=['redeem'])
def cmd_redeem(message):
    uid = message.from_user.id
    if is_authorized(uid):
        bot.reply_to(message, "You already have access.")
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Usage: /redeem <KEY>")
        return
    key = args[1].strip().upper()
    with data_lock:
        keys = load_keys()
        if key not in keys:
            bot.reply_to(message, "Invalid key. Contact: @Shennxs")
            return
        if keys[key]['status'] != 'active':
            bot.reply_to(message, "This key has already been used or revoked. Contact: @Shennxs")
            return
        keys[key]['status'] = 'used'
        save_keys(keys)
        users = load_users()
        users[uid] = {'name': message.from_user.first_name or str(uid), 'key': key}
        save_users(users)
    expiry = keys[key].get('expiry_ts', 0)
    exp_msg = ''
    if expiry > 0:
        remaining = expiry - int(time.time())
        if remaining > 0:
            exp_msg = f"\nExpires: {remaining // 86400}d {remaining % 86400 // 3600}h" if remaining >= 3600 else "\nExpires: < 1h"
    bot.reply_to(message,
        "Key activated! You now have access." + exp_msg + "\n\n"
        "/deviceid <id> — bind your device\n"
        "/on — start bruteforce on binded device\n"
        "/off — stop bruteforce\n"
        "/unbind_deviceid — unbind device\n"
        "/status — check status")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    uid = message.from_user.id
    if not is_authorized(uid):
        bot.reply_to(message, "No access. Contact: @Shennxs")
        return
    users = load_users()
    keys = load_keys()
    devs = load_devices()
    key = users.get(uid, {}).get('key', '')
    exp_str = ''
    if key and key in keys:
        expiry = keys[key].get('expiry_ts', 0)
        if expiry > 0:
            remaining = expiry - int(time.time())
            if remaining > 0:
                d = remaining // 86400
                h = remaining % 86400 // 3600
                exp_str = f"\nLicense: {d}d {h}h remaining" if d else f"\nLicense: {h}h remaining"
            else:
                exp_str = "\nLicense: EXPIRED"
        else:
            exp_str = "\nLicense: lifetime"
    bot.reply_to(message,
        f"Status for user {uid}:{exp_str}\n"
        f"Active sessions: {sum(1 for s in device_sessions.values() if s['uid'] == uid)}"
        f"\nBinded device: {devs.get(uid, {}).get('device_id', 'None')}")

@bot.message_handler(commands=['deviceid'])
def cmd_deviceid(message):
    uid = message.from_user.id
    if not is_authorized(uid):
        bot.reply_to(message, "No access. Contact: @Shennxs")
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Usage: /deviceid <device_id>")
        return
    device_id = args[1].strip()
    if not is_valid_device_id(device_id):
        bot.reply_to(message, "Incorrect device ID format!\n\n"
            "Android example: and_<hash>_<aid>_<adv>\n"
            "iOS example: ios_<uuid>")
        return
    with data_lock:
        devs = load_devices()
        devs[uid] = {'name': message.from_user.first_name or str(uid), 'device_id': device_id}
        save_devices(devs)
    bot.reply_to(message, f"Device ID binded successfully!\n`{device_id[:40]}...`")

@bot.message_handler(commands=['on'])
def cmd_on(message):
    uid = message.from_user.id
    if not is_authorized(uid):
        bot.reply_to(message, "No access. Contact: @Shennxs")
        return
    with data_lock:
        devs = load_devices()
    if uid not in devs or not devs[uid].get('device_id'):
        bot.reply_to(message, "No device ID binded. Use /deviceid <id> first.")
        return
    device_id = devs[uid]['device_id']
    if device_id in device_sessions:
        bot.reply_to(message, "Bruteforce is already running!")
        return
    cancel = threading.Event()
    threads = []
    def worker(did, c):
        while not c.is_set():
            st, r = tcp_kick_account(did, GLOBAL_SERVERS[0][0], GLOBAL_SERVERS[0][1])
            with data_lock:
                if st is True: stats['total_kicks'] += 1
                else: stats['failed'] += 1
            c.wait(1)
    for _ in range(50):
        t = threading.Thread(target=worker, args=(device_id, cancel), daemon=True)
        t.start()
        threads.append(t)
    device_sessions[device_id] = {'uid': uid, 'cancel': cancel, 'threads': threads}
    bot.reply_to(message, "🚀 Bruteforce is on!")

@bot.message_handler(commands=['off'])
def cmd_off(message):
    uid = message.from_user.id
    if not is_authorized(uid):
        bot.reply_to(message, "No access. Contact: @Shennxs")
        return
    with data_lock:
        devs = load_devices()
    if uid not in devs or not devs[uid].get('device_id'):
        bot.reply_to(message, "No device ID binded. Use /deviceid <id> first.")
        return
    device_id = devs[uid]['device_id']
    if device_id not in device_sessions:
        bot.reply_to(message, "No active session found.")
        return
    if device_sessions[device_id]['uid'] != uid and not is_admin(uid):
        bot.reply_to(message, "This session belongs to another user.")
        return
    device_sessions[device_id]['cancel'].set()
    del device_sessions[device_id]
    bot.reply_to(message, "⏹ Bruteforce is off!")

@bot.message_handler(commands=['unbind_deviceid'])
def cmd_unbind_deviceid(message):
    uid = message.from_user.id
    if not is_authorized(uid):
        bot.reply_to(message, "No access. Contact: @Shennxs")
        return
    with data_lock:
        devs = load_devices()
        if uid in devs:
            del devs[uid]
            save_devices(devs)
    # Also stop any active session for this user
    for did, sess in list(device_sessions.items()):
        if sess['uid'] == uid:
            sess['cancel'].set()
            del device_sessions[did]
    bot.reply_to(message, "Successfully unbinded! Use /deviceid <deviceid> to bind new device id.")

# --- Admin commands ---

@bot.message_handler(commands=['genkey'])
def cmd_genkey(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    args = message.text.split(maxsplit=1)
    duration_str = args[1].strip() if len(args) > 1 else ''
    expiry_ts = 0
    duration_label = 'never expires'
    if duration_str:
        m = re.match(r'^(\d+)\s*(h|hr|hours?|d|day|days?|w|week|weeks?|m|month|months?)$', duration_str, re.IGNORECASE)
        if not m:
            bot.reply_to(message, "Invalid duration. Examples: 24h, 7d, 2w, 1m")
            return
        num = int(m.group(1))
        unit = m.group(2).lower()[0]
        multiplier = {'h': 3600, 'd': 86400, 'w': 604800, 'm': 2592000}[unit]
        expiry_ts = int(time.time()) + num * multiplier
        duration_label = f"{num}{unit}"
    key = gen_key()
    with data_lock:
        keys = load_keys()
        keys[key] = {'status': 'active', 'created_by': uid, 'expiry_ts': expiry_ts}
        save_keys(keys)
    bot.reply_to(message, f"Key generated.\nDuration: {duration_label}\n\nUser redeems with:\n/redeem {key}")
    bot.send_message(message.chat.id, f"`{key}`", parse_mode="Markdown")

@bot.message_handler(commands=['keys'])
def cmd_keys(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    with data_lock:
        keys = load_keys()
    if not keys:
        bot.reply_to(message, "No keys.")
        return
    lines = ["Keys:"]
    for k, v in sorted(keys.items()):
        expiry = v.get('expiry_ts', 0)
        exp_str = ''
        if expiry > 0:
            remaining = expiry - int(time.time())
            if remaining > 0:
                exp_str = f" ({remaining // 3600}h left)" if remaining < 86400 else f" ({remaining // 86400}d left)"
            else:
                exp_str = " (EXPIRED)"
        lines.append(f"  {k} — {v['status']}{exp_str}")
    bot.reply_to(message, "\n".join(lines))

@bot.message_handler(commands=['users'])
def cmd_users(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    with data_lock:
        users = load_users()
    if not users:
        bot.reply_to(message, "No users.")
        return
    send_users_page(message.chat.id, users, 0)

def _users_page_text(users, page):
    per_page = 5
    items = sorted(users.items())
    total = len(items)
    pages = (total + per_page - 1) // per_page
    page = max(0, min(page, pages - 1))
    start = page * per_page
    batch = items[start:start + per_page]
    lines = [f"Users (page {page + 1}/{pages}):"]
    for uid2, v in batch:
        k = v.get('key', '')
        name = v.get('name', '?')
        lines.append(f"\n{uid2} — {name}\nKey: `{k}`")
    return "\n".join(lines), page, pages

def _users_page_markup(page, pages):
    markup = types.InlineKeyboardMarkup(row_width=2)
    btns = []
    if page > 0:
        btns.append(types.InlineKeyboardButton("◀ Back", callback_data=f"users_p:{page - 1}"))
    if page < pages - 1:
        btns.append(types.InlineKeyboardButton("Next ▶", callback_data=f"users_p:{page + 1}"))
    if btns: markup.add(*btns)
    return markup

def send_users_page(chat_id, users, page):
    text, page, pages = _users_page_text(users, page)
    bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=_users_page_markup(page, pages))

@bot.callback_query_handler(func=lambda c: c.data.startswith("users_p:"))
def users_page_callback(call):
    page = int(call.data.split(":")[1])
    with data_lock:
        users = load_users()
    if not users:
        bot.answer_callback_query(call.id, "No users.")
        return
    text, page, pages = _users_page_text(users, page)
    bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="Markdown", reply_markup=_users_page_markup(page, pages))
    bot.answer_callback_query(call.id)

@bot.message_handler(commands=['ban'])
def cmd_ban(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    args = message.text.split(maxsplit=2)
    if len(args) < 2:
        bot.reply_to(message, "Usage: /ban <user_id>")
        return
    try:
        target = int(args[1])
    except ValueError:
        bot.reply_to(message, "Invalid user ID.")
        return
    with data_lock:
        users = load_users()
        if target in users:
            del users[target]
            save_users(users)
    if target in cancel_events:
        cancel_events[target].set()
    bot.reply_to(message, f"User {target} banned.")

@bot.message_handler(commands=['revoke'])
def cmd_revoke(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Usage: /revoke <LICENCE_KEY>")
        return
    key = args[1].strip().upper()
    with data_lock:
        keys = load_keys()
        if key not in keys:
            bot.reply_to(message, "Key not found.")
            return
        keys[key]['status'] = 'revoked'
        save_keys(keys)
        users = load_users()
        for uid2, v in list(users.items()):
            if v.get('key') == key:
                if uid2 in cancel_events:
                    cancel_events[uid2].set()
                del users[uid2]
        save_users(users)
    bot.reply_to(message, f"Key `{key[:12]}...` revoked. User removed and kicked if active.")

@bot.message_handler(commands=['announcement'])
def cmd_announcement(message):
    uid = message.from_user.id
    if not is_admin(uid):
        bot.reply_to(message, "Admin only.")
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        bot.reply_to(message, "Usage: /announcement <message>")
        return
    text = args[1].strip()
    sent = 0
    with data_lock:
        users = load_users()
    targets = set(users.keys()) | set(ADMIN_IDS)
    for uid2 in targets:
        try:
            bot.send_message(uid2, f"📢 Announcement:\n{text}")
            sent += 1
        except:
            pass
    bot.reply_to(message, f"Announcement sent to {sent}/{len(targets)} users.")

if __name__ == '__main__':
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("[!] Edit config.py and set your BOT_TOKEN first.")
        sys.exit(1)

    user_commands = [
        types.BotCommand("start", "Welcome & info"),
        types.BotCommand("redeem", "Activate license key"),
        types.BotCommand("deviceid", "Bind your device ID"),
        types.BotCommand("on", "Start bruteforce"),
        types.BotCommand("off", "Stop bruteforce"),
        types.BotCommand("unbind_deviceid", "Unbind device ID"),
        types.BotCommand("status", "Check current status"),
    ]
    admin_commands = user_commands + [
        types.BotCommand("genkey", "Generate a license key"),
        types.BotCommand("keys", "List all keys"),
        types.BotCommand("users", "List all users"),
        types.BotCommand("revoke", "Revoke a license key"),
        types.BotCommand("ban", "Ban a user"),
        types.BotCommand("announcement", "Broadcast to all users"),
    ]

    try:
        bot.set_my_commands(user_commands, scope=types.BotCommandScopeAllPrivateChats())
        for aid in ADMIN_IDS:
            bot.set_my_commands(admin_commands, scope=types.BotCommandScopeChat(chat_id=aid))
    except Exception as e:
        print(f"[!] Failed to set commands: {e}")

    print("Bot running...")
    while True:
        try:
            bot.infinity_polling(none_stop=True, skip_pending=True, timeout=30, long_polling_timeout=30)
        except Exception as e:
            print(f"[!] Polling error: {e}, restarting in 3s...")
            time.sleep(3)
