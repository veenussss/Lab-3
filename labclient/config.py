"""Local (git-ignored) connection settings."""
import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "config.local.json")
DEFAULTS = {"host": "", "port": 8080, "username": "", "timeout": 30}


def load(path: str = CONFIG_PATH) -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update({k: data[k] for k in DEFAULTS if k in data})
    except (OSError, ValueError):
        pass
    return cfg


def save(cfg: dict, path: str = CONFIG_PATH) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({k: cfg.get(k, v) for k, v in DEFAULTS.items()}, f, indent=2)
    except OSError:
        pass
