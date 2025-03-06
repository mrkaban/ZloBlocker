import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "app_name": "ZloBlocker",
    "version": "1.0",
    "author": "Алексей Черемных",
    "email": "info@mrkaban.ru",
    "site": "alekseycheremnykh.ru",
    "update_interval": 60,
    "hosts_url": ""
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)

def save_selected_lists(selected_lists):
    config = load_config()
    config["selected_lists"] = selected_lists
    save_config(config)

def load_selected_lists():
    config = load_config()
    return config.get("selected_lists", [])
