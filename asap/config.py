from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from . import CATEGORIES, CATEGORY_ALIASES

@dataclass
class Config:
    categories: list[str] = field(default_factory=lambda: list(CATEGORIES))
    exclude: list[str] = field(default_factory=lambda: [
        ".git/**", "**/.git/**", "**/original/**", "**/node_modules/**",
        "**/.gradle/**", "**/R.java", "**/R$*.java", "**/BuildConfig.java",
    ])
    include_vendor: bool = False
    workers: int = 4
    max_files: int = 50000
    max_file_bytes: int = 4 * 1024 * 1024
    max_source_bytes: int = 256 * 1024 * 1024
    max_archive_bytes: int = 2 * 1024 * 1024 * 1024
    max_entry_bytes: int = 512 * 1024 * 1024
    max_compression_ratio: int = 250
    tool_timeout: int = 600
    jadx: str | None = None
    apktool: str | None = None
    firebase_rules: str | None = None
    firebase_data: str | None = None
    decompile: bool = True
    suppressions: list[dict] = field(default_factory=list)

    def validate(self) -> None:
        if not isinstance(self.categories,list) or not all(isinstance(c,str) for c in self.categories):
            raise ValueError("categories must be a list of category names")
        self.categories = list(dict.fromkeys(CATEGORY_ALIASES.get(c, c) for c in self.categories))
        if not self.categories or set(self.categories) - set(CATEGORIES):
            raise ValueError("categories must contain only the seven supported categories")
        if type(self.workers) is not int or not 1 <= self.workers <= 32:
            raise ValueError("workers must be between 1 and 32")
        for key in ("max_files", "max_file_bytes", "max_source_bytes", "max_archive_bytes",
                    "max_entry_bytes", "max_compression_ratio", "tool_timeout"):
            if type(getattr(self, key)) is not int or getattr(self, key) <= 0:
                raise ValueError(f"{key} must be a positive integer")
        for k in ("include_vendor", "decompile"):
            if type(getattr(self, k)) is not bool:
                raise ValueError(f"{k} must be boolean")
        for key in ("firebase_rules", "firebase_data"):
            value = getattr(self, key)
            if value is not None and (not isinstance(value, str) or not value.strip() or '\x00' in value):
                raise ValueError(f"{key} must be a non-empty local file path or null")
            if isinstance(value, str) and '://' in value:
                raise ValueError(f"{key} requires a local file path")
        if not isinstance(self.exclude, list) or not all(isinstance(x, str) for x in self.exclude):
            raise ValueError("exclude must be a list of glob patterns")
        if not isinstance(self.suppressions, list):
            raise ValueError("suppressions must be a list")
        for s in self.suppressions:
            if not isinstance(s, dict) or not isinstance(s.get("reason"), str) or not s["reason"].strip():
                raise ValueError("each suppression requires a non-empty reason")
            if not (s.get("fingerprint") or (s.get("rule_id") and s.get("path"))):
                raise ValueError("suppression requires fingerprint or rule_id + path")
            if set(s) - {"reason", "fingerprint", "rule_id", "path", "expires"}:
                raise ValueError("unknown suppression key")
            if s.get("expires"):
                from datetime import date
                date.fromisoformat(s["expires"])

    @classmethod
    def load(cls, path: Path | None) -> "Config":
        if path is None:
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("unknown configuration keys or invalid configuration object")
        obj = cls(**raw)
        obj.validate()
        return obj

    def to_dict(self) -> dict:
        return asdict(self)
