"""Rule and settings loading: built-in rules.toml plus an optional user .gitsecrets.toml."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

CONFIG_NAME = ".gitsecrets.toml"
_USER_KEYS = {"disable_rules", "rules", "entropy", "allowlist"}


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    regex: re.Pattern[str]
    group: int = 0
    keywords: tuple[str, ...] = ()
    min_entropy: float = 0.0
    allowlist: tuple[re.Pattern[str], ...] = ()


@dataclass
class Config:
    rules: list[Rule] = field(default_factory=list)
    entropy: bool = True
    b64_threshold: float = 4.2
    hex_threshold: float = 3.0
    decode_base64: bool = True
    ignore_paths: list[str] = field(default_factory=list)
    allow_regexes: list[re.Pattern[str]] = field(default_factory=list)


def _compile(pattern: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as e:
        raise ConfigError(f"{where}: invalid regex {pattern!r}: {e}") from e


def _parse_rule(d: dict, where: str) -> Rule:
    for key in ("id", "description", "regex"):
        if key not in d:
            raise ConfigError(f"{where}: rule is missing '{key}'")
    rx = _compile(d["regex"], where)
    group = int(d.get("group", 0))
    if group > rx.groups:
        raise ConfigError(f"{where}: group {group} but regex has {rx.groups} group(s)")
    return Rule(d["id"], d["description"], rx, group,
                tuple(k.lower() for k in d.get("keywords", [])),
                float(d.get("min_entropy", 0.0)),
                tuple(_compile(a, where) for a in d.get("allowlist", [])))


def builtin_rules() -> list[Rule]:
    text = resources.files("gitsecrets").joinpath("rules.toml").read_text("utf-8")
    return [_parse_rule(r, f"rules.toml rule #{i + 1}")
            for i, r in enumerate(tomllib.loads(text)["rules"])]


def _apply_user(cfg: Config, path: Path) -> None:
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path}: {e}") from e
    unknown = set(data) - _USER_KEYS
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {sorted(unknown)}; allowed: {sorted(_USER_KEYS)}")
    disabled = set(data.get("disable_rules", []))
    cfg.rules = [r for r in cfg.rules if r.id not in disabled]
    for i, d in enumerate(data.get("rules", [])):
        rule = _parse_rule(d, f"{path} rule #{i + 1}")
        cfg.rules = [r for r in cfg.rules if r.id != rule.id] + [rule]
    ent = data.get("entropy", {})
    cfg.entropy = bool(ent.get("enabled", cfg.entropy))
    cfg.b64_threshold = float(ent.get("b64_threshold", cfg.b64_threshold))
    cfg.hex_threshold = float(ent.get("hex_threshold", cfg.hex_threshold))
    cfg.decode_base64 = bool(ent.get("decode_base64", cfg.decode_base64))
    allow = data.get("allowlist", {})
    cfg.ignore_paths += list(allow.get("paths", []))
    cfg.allow_regexes += [_compile(p, f"{path} allowlist") for p in allow.get("regexes", [])]


def load_config(root: str | None = None, path: str | None = None) -> Config:
    cfg = Config(rules=builtin_rules())
    if path:
        if not Path(path).is_file():
            raise ConfigError(f"config file not found: {path}")
        _apply_user(cfg, Path(path))
    elif root and (Path(root) / CONFIG_NAME).is_file():
        _apply_user(cfg, Path(root) / CONFIG_NAME)
    return cfg
