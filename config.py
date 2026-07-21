import os

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8882393557:AAGLyUD-P10dhN-Wd4MQrWZN99aG2tSSb-c")
ADMIN_IDS = [
    int(x) for x in os.environ.get("ADMIN_IDS", "7410975556").split(",") if x.strip()
]
KEYS_FILE = os.environ.get("KEYS_FILE", "keys.txt")
USERS_FILE = os.environ.get("USERS_FILE", "users.txt")
DEVICES_FILE = os.environ.get("DEVICES_FILE", "devices.txt")
