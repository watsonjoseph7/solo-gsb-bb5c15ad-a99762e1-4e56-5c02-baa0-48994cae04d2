"""Pydantic models for the HTTP API (pydantic v2)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .analyzer import ValidationError, normalize_action


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(..., description="IPv4/IPv6 network in CIDR notation; host bits must be zero")
    action: str = Field(..., description="permit/allow or deny/block/drop/reject")
    priority: int = Field(
        default=100, ge=0, description="Smaller number = higher priority; only breaks same-CIDR ties"
    )
    source_tag: str = Field(default="default", description="Label of the rule's origin")
    rule_id: str | None = Field(default=None, description="Optional unique id; auto-generated as r1, r2...")

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("cidr", "source_tag")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleIn] = Field(..., min_length=1, description="Ordered rule set")
    name: str | None = Field(default=None, description="Optional human-readable version name")
    save: bool = Field(default=True, description="Persist this analysis as an immutable version")


class RuleAdd(RuleIn):
    """A brand-new rule for a simulation batch; the id must not exist yet."""

    rule_id: str = Field(..., description="Unique id of the new rule; must not exist in the base version")


class RuleReplace(RuleIn):
    """Full replacement record of an existing rule (id must hit the base version)."""

    rule_id: str = Field(..., description="rule_id of the base-version rule to replace")


class RuleRemove(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="rule_id of the base-version rule to remove")

    @field_validator("rule_id")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    add: list[RuleAdd] = Field(
        default_factory=list,
        description="Rules to append; rule_ids must be new (no overlap with the base version)",
    )
    replace: list[RuleReplace] = Field(
        default_factory=list,
        description="Existing rules to rewrite in place; rule_ids must hit the base version",
    )
    remove: list[RuleRemove] = Field(
        default_factory=list,
        description="Existing rules to delete; rule_ids must hit the base version",
    )

    @field_validator("add", "replace", "remove", mode="before")
    @classmethod
    def _must_be_list(cls, v: Any) -> Any:
        if not isinstance(v, list):
            raise ValueError("must be a list of operations")
        return v


class ListAnalysesResponse(BaseModel):
    total: int
    analyses: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
