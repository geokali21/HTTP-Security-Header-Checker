"""Data models shared by the checker, reports, and tests."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Status(str, Enum):
    FOUND = "FOUND"
    MISSING = "MISSING"
    REVIEW = "REVIEW"


@dataclass
class HeaderFinding:
    name: str
    status: Status
    observed_value: Optional[str]
    reason: str          # why this status was assigned (the observation)
    purpose: str
    risk: str            # potential risk, NOT a confirmed vulnerability
    mitigation: str
    verification: str
    limitation: str


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    redirect_chain: List[str]
    headers: Dict[str, str]
    elapsed_ms: int
    notes: List[str] = field(default_factory=list)


@dataclass
class Report:
    tool: str
    version: str
    generated_at: str
    target: str
    final_url: str
    status_code: int
    redirect_chain: List[str]
    elapsed_ms: int
    findings: List[HeaderFinding]
    summary: Dict[str, int]
    notes: List[str]
    disclaimer: str
