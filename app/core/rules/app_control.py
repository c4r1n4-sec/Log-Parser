"""Deterministic Carbon Black App Control rule-pack loading and matching."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.core.util.paths import app_root


@dataclass(frozen=True)
class AppControlRule:
    """One compiled App Control rule definition."""

    rule_id: str
    severity: str
    product: str
    issue_category: str
    component: str
    kb_candidates: tuple[str, ...]
    false_positive_cautions: str
    required_evidence: tuple[str, ...]
    missing_evidence: str
    patterns: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class RuleMatch:
    """A regex match against an App Control rule."""

    rule: AppControlRule
    matched_text: str


@lru_cache(maxsize=1)
def load_app_control_rules() -> tuple[AppControlRule, ...]:
    """Load and compile the bundled App Control JSON rule pack."""
    rules_path = app_root() / "rules" / "app_control_rules.json"
    with rules_path.open("r", encoding="utf-8") as rules_file:
        payload: dict[str, Any] = json.load(rules_file)

    compiled_rules: list[AppControlRule] = []
    for rule_data in payload.get("rules", []):
        compiled_rules.append(
            AppControlRule(
                rule_id=str(rule_data["rule_id"]),
                severity=str(rule_data["severity"]),
                product=str(rule_data["product"]),
                issue_category=str(rule_data["issue_category"]),
                component=str(rule_data["component"]),
                kb_candidates=tuple(str(item) for item in rule_data.get("kb_candidates", [])),
                false_positive_cautions=str(rule_data.get("false_positive_cautions", "")),
                required_evidence=tuple(
                    str(item) for item in rule_data.get("required_evidence", [])
                ),
                missing_evidence=str(rule_data.get("missing_evidence", "")),
                patterns=tuple(
                    re.compile(str(pattern), re.IGNORECASE)
                    for pattern in rule_data.get("patterns", [])
                ),
            )
        )
    return tuple(compiled_rules)


def match_app_control_rules(text: str) -> list[RuleMatch]:
    """Return deterministic App Control rule matches for a text fragment."""
    matches: list[RuleMatch] = []
    for rule in load_app_control_rules():
        for pattern in rule.patterns:
            match = pattern.search(text)
            if match is not None:
                matches.append(RuleMatch(rule=rule, matched_text=match.group(0)))
                break
    return matches
