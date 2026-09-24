"""Change guard: authorize effective-action transitions between two versions.

Given two stored analysis results (a *base* and a *target*) and a list of
*authorization entries*, each one stating a strict CIDR plus the exact
``from_action`` / ``to_action`` transition permitted there, this module checks
the two versions' **final effective action** diff segment by segment:

* an address whose action changed is *authorized* only when it falls inside an
  authorization entry of the **same IP family** whose declared transition is
  exactly the change it underwent (``permit`` / ``deny`` / ``none``);
* entries authorizing the **same** transition kind are combined by union, so
  nested and duplicate entries accumulate naturally;
* entries authorizing **different** transition kinds must never overlap
  (otherwise the intended meaning at the overlap is ambiguous) — the whole
  request is rejected with :class:`GuardError` listing every clash;
* an authorization over an area that does **not** change is harmless: an
  unchanged region is never a violation.

The check reuses the effective-action partition/overlay machinery of
:mod:`app.diff` and is purely geometric — networks are carved into disjoint
CIDR cells and collapsed with ``ipaddress.collapse_addresses``; addresses are
never enumerated, so IPv6 spaces (up to 2**128 addresses) are handled exactly.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .analyzer import _sort_networks, _subtract
from .diff import (
    CHANGE_TYPE_ORDER,
    Action,
    Network,
    change_type_name,
    _effective_partition,
    _overlay,
    _split_by_version,
)

#: The three accepted action spellings; ``"none"`` stands for "no rule matches".
ACTIONS: tuple[str, str, str] = ("permit", "deny", "none")

#: Sentinel for an action string that failed validation.
_INVALID: Any = object()


class GuardError(ValueError):
    """The authorization request is invalid as a whole.

    ``issues`` collects every problem at once (bad CIDRs, equal/unknown
    actions, cross-kind overlaps), mirroring :class:`~app.simulate.PatchError`.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class Authorization:
    """One declared transition permission over a strict CIDR."""

    index: int
    network: Network
    from_action: Action  # ``None`` encodes ``none``
    to_action: Action

    @property
    def kind(self) -> tuple[Action, Action]:
        return (self.from_action, self.to_action)

    @property
    def number(self) -> int:
        """1-based position of the entry in the request (for messages)."""
        return self.index + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "cidr": str(self.network),
            "ip_version": self.network.version,
            "from_action": self.from_action,
            "to_action": self.to_action,
        }


# ---------------------------------------------------------------------------
# Request parsing / structural validation
# ---------------------------------------------------------------------------
def _parse_strict_cidr(raw: Any, pos: int, issues: list[str]) -> Network | None:
    """Parse a strict IPv4/IPv6 CIDR (explicit prefix length, host bits zero)."""
    if not isinstance(raw, str) or not raw.strip():
        issues.append(f"authorization #{pos}: cidr is required and must be a non-empty string")
        return None
    text = raw.strip()
    if "/" not in text:
        issues.append(
            f"authorization #{pos}: invalid CIDR {raw!r}; an explicit prefix length is "
            "required (e.g. '10.0.0.0/8')"
        )
        return None
    try:
        # strict=True rejects host bits, e.g. 10.0.0.5/24 and 2001:db8::1/32.
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        issues.append(f"authorization #{pos}: invalid CIDR {raw!r} ({exc})")
        return None


def _parse_action(raw: Any, pos: int, field: str, issues: list[str]) -> Action:
    """Parse one permit/deny/none action; ``"none"`` becomes ``None``."""
    if not isinstance(raw, str) or not raw.strip():
        issues.append(f"authorization #{pos}: {field} is required and must be one of {', '.join(ACTIONS)}")
        return _INVALID
    text = raw.strip().lower()
    if text not in ACTIONS:
        issues.append(
            f"authorization #{pos}: invalid {field} {raw!r}; expected one of {', '.join(ACTIONS)}"
        )
        return _INVALID
    return None if text == "none" else text


def _find_cross_kind_overlaps(auths: list[Authorization]) -> list[str]:
    """Return one issue per overlapping pair whose transition kinds differ.

    Same-kind entries are free to nest or repeat (their union authorizes the
    combined surface); entries of different IP families cannot overlap and are
    never compared.
    """
    issues: list[str] = []
    by_version: dict[int, list[Authorization]] = defaultdict(list)
    for auth in auths:
        by_version[auth.network.version].append(auth)

    for version, entries in by_version.items():
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                a, b = entries[i], entries[j]
                if a.kind == b.kind:
                    continue
                net_a, net_b = a.network, b.network
                if net_a.version != net_b.version:
                    continue
                if net_a == net_b or net_a.subnet_of(net_b) or net_b.subnet_of(net_a):
                    issues.append(
                        f"authorization #{a.number} ({change_type_name(a.from_action, a.to_action)} "
                        f"{net_a}) overlaps authorization #{b.number} "
                        f"({change_type_name(b.from_action, b.to_action)} {net_b}); entries for "
                        "different from_action/to_action transitions must be disjoint"
                    )
    return issues


def parse_authorizations(raw: Any) -> list[Authorization]:
    """Validate and parse the request's authorization entries.

    Every structural problem is collected and raised together as
    :class:`GuardError`.  Cross-kind overlap checks only run on entries that
    parsed successfully.
    """
    if not isinstance(raw, list) or not raw:
        raise GuardError(["authorizations must be a non-empty list"])

    issues: list[str] = []
    parsed: list[Authorization] = []
    for pos, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            issues.append(f"authorization #{pos}: must be an object")
            continue
        network = _parse_strict_cidr(entry.get("cidr"), pos, issues)
        from_action = _parse_action(entry.get("from_action"), pos, "from_action", issues)
        to_action = _parse_action(entry.get("to_action"), pos, "to_action", issues)
        if network is None or from_action is _INVALID or to_action is _INVALID:
            continue
        if from_action == to_action:
            issues.append(
                f"authorization #{pos}: from_action and to_action must differ "
                f"(got {from_action or 'none'} -> {to_action or 'none'})"
            )
            continue
        parsed.append(Authorization(pos - 1, network, from_action, to_action))

    issues.extend(_find_cross_kind_overlaps(parsed))
    if issues:
        raise GuardError(issues)
    return parsed


# ---------------------------------------------------------------------------
# Guard evaluation
# ---------------------------------------------------------------------------
def _subtract_union(network: Network, cutters: list[Network]) -> list[Network]:
    """``network`` minus the union of ``cutters`` (cutters may nest/repeat)."""
    if not cutters:
        return [network]
    # Intersect every cutter with the cell first: CIDRs never half-overlap, so
    # the intersection is the cell itself (cutter is a supernet), the cutter
    # (a subnet), or nothing (disjoint).  After collapsing, the cutters are
    # pairwise-disjoint subnets of the cell and subtraction is geometric.
    clipped: list[Network] = []
    for cutter in cutters:
        if cutter.version != network.version:
            continue
        if cutter == network or cutter.subnet_of(network):
            clipped.append(cutter)
        elif network.subnet_of(cutter):
            clipped.append(network)
    if not clipped:
        return [network]
    union = list(ipaddress.collapse_addresses(_sort_networks(clipped)))
    return _subtract(network, union)


def _changed_cells(base: dict[str, Any], target: dict[str, Any]) -> dict[
    int, dict[tuple[Action, Action], list[Network]]
]:
    """Overlay both versions per IP family and bucket changed cells by kind."""
    a_by_version = _split_by_version(_effective_partition(base))
    b_by_version = _split_by_version(_effective_partition(target))

    by_version: dict[int, dict[tuple[Action, Action], list[Network]]] = {}
    for version in (4, 6):
        cells = _overlay(a_by_version.get(version, []), b_by_version.get(version, []))
        by_kind: dict[tuple[Action, Action], list[Network]] = defaultdict(list)
        for net, a_action, b_action in cells:
            if a_action != b_action:
                by_kind[(a_action, b_action)].append(net)
        by_version[version] = by_kind
    return by_version


def build_change_guard(
    base: dict[str, Any],
    target: dict[str, Any],
    raw_authorizations: Any,
) -> dict[str, Any]:
    """Evaluate authorized transitions against the base->target diff.

    Output contract::

        {
          "base": {...}, "target": {...},
          "passed": bool,
          "authorizations": [{index, cidr, ip_version, from_action, to_action}],
          "violations": [
            {"ip_version": 4, "change_type": "...",
             "from_action": ..., "to_action": ...,
             "changed_address_count": N, "authorized_address_count": A,
             "unauthorized_address_count": U, "range_count": k,
             "cidrs": [<minimal unauthorized CIDRs>]}, ...
          ],
          "summary": {"total_changed_addresses": ...,
                      "total_authorized_addresses": ...,
                      "total_unauthorized_addresses": ...,
                      "violation_groups": ...,
                      "ipv4": {...}, "ipv6": {...}}
        }
    """
    authorizations = parse_authorizations(raw_authorizations)

    # Same-kind entries grouped per IP family; their union is the allowed mask.
    allowed: dict[int, dict[tuple[Action, Action], list[Network]]] = {
        4: defaultdict(list),
        6: defaultdict(list),
    }
    for auth in authorizations:
        allowed[auth.network.version][auth.kind].append(auth.network)

    changed = _changed_cells(base, target)

    violations: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "total_changed_addresses": 0,
        "total_authorized_addresses": 0,
        "total_unauthorized_addresses": 0,
        "violation_groups": 0,
    }

    for version in (4, 6):
        family_changed = 0
        family_authorized = 0
        family_unauthorized = 0
        family_groups = 0
        type_counts: dict[str, int] = {
            change_type_name(frm, to): 0 for frm, to in CHANGE_TYPE_ORDER
        }

        for frm, to in CHANGE_TYPE_ORDER:
            cells = changed[version].get((frm, to), [])
            if not cells:
                continue
            changed_count = sum(net.num_addresses for net in cells)

            unauthorized_pieces: list[Network] = []
            for cell in cells:
                # Only same-family, same-transition entries can authorize; the
                # cross-family space is unreachable here by construction.
                unauthorized_pieces.extend(_subtract_union(cell, allowed[version].get((frm, to), [])))

            unauthorized = list(
                ipaddress.collapse_addresses(_sort_networks(unauthorized_pieces))
            )
            unauthorized_count = sum(net.num_addresses for net in unauthorized)
            authorized_count = changed_count - unauthorized_count

            family_changed += changed_count
            family_authorized += authorized_count
            family_unauthorized += unauthorized_count
            type_counts[change_type_name(frm, to)] = unauthorized_count

            if unauthorized:
                family_groups += 1
                violations.append(
                    {
                        "ip_version": version,
                        "change_type": change_type_name(frm, to),
                        "from_action": frm,
                        "to_action": to,
                        "changed_address_count": changed_count,
                        "authorized_address_count": authorized_count,
                        "unauthorized_address_count": unauthorized_count,
                        "range_count": len(unauthorized),
                        "cidrs": [str(net) for net in unauthorized],
                    }
                )

        summary[f"ipv{version}"] = {
            "changed_addresses": family_changed,
            "authorized_addresses": family_authorized,
            "unauthorized_addresses": family_unauthorized,
            "violation_groups": family_groups,
            "unauthorized_by_type": type_counts,
        }
        summary["total_changed_addresses"] += family_changed
        summary["total_authorized_addresses"] += family_authorized
        summary["total_unauthorized_addresses"] += family_unauthorized
        summary["violation_groups"] += family_groups

    return {
        "base": {
            "id": base.get("id"),
            "ruleset_hash": base.get("ruleset_hash"),
            "analyzer_version": base.get("analyzer_version"),
        },
        "target": {
            "id": target.get("id"),
            "ruleset_hash": target.get("ruleset_hash"),
            "analyzer_version": target.get("analyzer_version"),
        },
        "passed": summary["total_unauthorized_addresses"] == 0,
        "authorizations": [auth.as_dict() for auth in authorizations],
        "violations": violations,
        "summary": summary,
    }
