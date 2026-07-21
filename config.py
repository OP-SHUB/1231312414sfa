import os

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8276709487:AAEYesKZxhj7zBLxKi16UqUFJkqlRn7VB9o")
ADMIN_IDS = [
    int(x) for x in os.environ.get("ADMIN_IDS", "7410975556").split(",") if x.strip()
]
KEYS_FILE = os.environ.get("KEYS_FILE", "keys.txt")
USERS_FILE = os.environ.get("USERS_FILE", "users.txt")
PROXY_URL = os.environ.get("PROXY_URL", "http://847c2f5c4463782e551a:3c060617ca5eb1de@gw.dataimpulse.com:823")
