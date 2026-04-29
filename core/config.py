"""
Модуль для работы с глобальной конфигурацией.
Загружает параметры из config.yaml, предоставляет значения по умолчанию.
"""
import os
from pathlib import Path
import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"

def load_config(config_path: Path = None) -> dict:
    if config_path is None:
        config_path = _DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return _default_config()
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return _merge_with_defaults(cfg)

def save_config(config_dict: dict, config_path: Path = None) -> None:
    """Сохраняет словарь в YAML‑файл конфигурации."""
    if config_path is None:
        config_path = _DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, allow_unicode=True)

def _default_config() -> dict:
    return {
        "ida": {
            "idat64": "idat.exe",
            "idat32": "idat.exe",
        },
        "max_ida": 4,
        "default_inputdir": ".",
        "log_level": "INFO",
        "theme": "light",
    }

def _merge_with_defaults(user_cfg: dict) -> dict:
    default = _default_config()
    for key, value in default.items():
        if key not in user_cfg:
            user_cfg[key] = value
    if "ida" not in user_cfg:
        user_cfg["ida"] = default["ida"]
    else:
        for subkey, subval in default["ida"].items():
            if subkey not in user_cfg["ida"]:
                user_cfg["ida"][subkey] = subval
    return user_cfg

def get_ida_executable(arch="64") -> str:
    cfg = load_config()
    key = f"idat{arch}"
    if "ida" in cfg and key in cfg["ida"]:
        return cfg["ida"][key]
    return f"idat{arch}.exe"

def get_max_ida() -> int:
    return load_config().get("max_ida", 4)

def get_default_inputdir() -> str:
    return load_config().get("default_inputdir", ".")