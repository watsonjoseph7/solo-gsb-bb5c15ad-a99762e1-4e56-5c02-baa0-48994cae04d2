"""End-to-end tests for POST /api/analyses/{base}/change-guard/{target}."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-guard-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _guard(
    client: TestClient,
    base_id: str,
    target_id: str,
    authorizations: list[dict],
):
    return client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}",
        json={"authorizations": authorizations},
    )


# ---------------------------------------------------------------------------
# Fixture versions
# ---------------------------------------------------------------------------
@pytest.fixture()
def nested_pair(client: TestClient) -> tuple[str, str]:
    # base: flat permit /8
    # target: deny /16 around an unchanged permit /24
    base_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}], name="v1")
    target_id = _save(
        client,
        [
            {"cidr": "10.1.0.0/16", "action": "deny"},
            {"cidr": "10.1.1.0/24", "action": "permit"},
        ],
        name="v2",
    )
    return base_id, target_id


# /16 minus 10.1.1.0/24 as minimal CIDRs — the exact permit->deny surface.
DENY_FLIP_CIDRS = [
    "10.1.0.0/24",
    "10.1.2.0/23",
    "10.1.4.0/22",
    "10.1.8.0/21",
    "10.1.16.0/20",
    "10.1.32.0/19",
    "10.1.64.0/18",
    "10.1.128.0/17",
]
# /8 minus /16 as minimal CIDRs — the exact permit->none surface.
NONE_FLIP_CIDRS = [
    "10.0.0.0/16",
    "10.2.0.0/15",
    "10.4.0.0/14",
    "10.8.0.0/13",
    "10.16.0.0/12",
    "10.32.0.0/11",
    "10.64.0.0/10",
    "10.128.0.0/9",
]


# ---------------------------------------------------------------------------
def test_fully_authorized_change_passes(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair
    auths = [{"cidr": c, "from_action": "permit", "to_action": "deny"} for c in DENY_FLIP_CIDRS]
    auths += [{"cidr": c, "from_action": "permit", "to_action": "none"} for c in NONE_FLIP_CIDRS]

    r = _guard(client, base_id, target_id, auths)
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is True
    assert payload["violations"] == []
    # 65280 addresses flipped permit->deny, 16711680 permit->none; the /24
    # stayed permit and is not counted anywhere.
    s = payload["summary"]
    assert s["ipv4"]["changed_addresses"] == 2 ** 24 - 2 ** 8
    assert s["ipv4"]["authorized_addresses"] == 2 ** 24 - 2 ** 8
    assert s["ipv4"]["unauthorized_addresses"] == 0
    assert s["total_unauthorized_addresses"] == 0
    assert s["violation_groups"] == 0
    assert len(payload["authorizations"]) == len(auths)
    assert payload["base"]["id"] == base_id
    assert payload["target"]["id"] == target_id


def test_unauthorized_change_reports_minimal_cidrs_and_exact_counts(
    client: TestClient, nested_pair
) -> None:
    base_id, target_id = nested_pair
    # Authorize only part of the deny-flip: the /24 sibling 10.1.0.0/24.
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"}],
    )
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["passed"] is False
    by_type = {v["change_type"]: v for v in payload["violations"]}

    # permit->deny surface was 65280; 256 authorized -> 65024 unauthorized.
    deny_flip = by_type["permit_to_deny"]
    assert deny_flip["changed_address_count"] == 2 ** 16 - 2 ** 8
    assert deny_flip["authorized_address_count"] == 2 ** 8
    assert deny_flip["unauthorized_address_count"] == 2 ** 16 - 2 ** 9
    assert deny_flip["from_action"] == "permit"
    assert deny_flip["to_action"] == "deny"
    assert deny_flip["range_count"] == len(deny_flip["cidrs"])
    # The authorized /24 must be absent from the unauthorized minimal list.
    assert "10.1.0.0/24" not in deny_flip["cidrs"]
    assert "10.1.2.0/23" in deny_flip["cidrs"]

    # Nothing outside /16 was authorized for permit->none.
    none_flip = by_type["permit_to_none"]
    assert none_flip["cidrs"] == NONE_FLIP_CIDRS
    assert none_flip["unauthorized_address_count"] == 2 ** 24 - 2 ** 16
    assert none_flip["authorized_address_count"] == 0


def test_authorization_must_match_the_actual_transition(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair
    # Same CIDR surface, but the declared transition is wrong: every changed
    # address stays unauthorized (and no cross-kind overlap because the other
    # entries use a disjoint surface).
    r = _guard(
        client,
        base_id,
        target_id,
        [
            {"cidr": "10.1.0.0/24", "from_action": "deny", "to_action": "permit"},
        ],
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["passed"] is False
    deny_flip = next(v for v in payload["violations"] if v["change_type"] == "permit_to_deny")
    assert deny_flip["authorized_address_count"] == 0
    assert deny_flip["unauthorized_address_count"] == 2 ** 16 - 2 ** 8
    assert "10.1.0.0/24" in deny_flip["cidrs"]


def test_same_kind_nested_and_duplicate_entries_combine_as_union(
    client: TestClient, nested_pair
) -> None:
    base_id, target_id = nested_pair
    # A broad permit->deny entry over /16 plus a nested and an exact duplicate
    # /24 entry: all same kind, the union authorizes the whole deny-flip
    # (10.1.1.0/24 is unchanged permit and is simply not part of the surface).
    r = _guard(
        client,
        base_id,
        target_id,
        [
            {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"},
            {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},
            {"cidr": "10.1.0.0/24", "from_action": "permit", "to_action": "deny"},
        ],
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert not [v for v in payload["violations"] if v["change_type"] == "permit_to_deny"]
    deny_summary = payload["summary"]["ipv4"]
    # deny-flip fully authorized (65280); permit->none surface still violates.
    assert deny_summary["unauthorized_by_type"]["permit_to_deny"] == 0
    assert deny_summary["unauthorized_by_type"]["permit_to_none"] == 2 ** 24 - 2 ** 16


def test_authorization_supernet_covers_smaller_change_cells(client: TestClient) -> None:
    # base permit /16; target flips two disjoint /24s to deny.  One broad
    # permit->deny entry on the /16 authorizes both cells; the unchanged rest
    # of the /16 is not a violation.
    base_id = _save(client, [{"cidr": "10.1.0.0/16", "action": "permit"}])
    target_id = _save(
        client,
        [
            {"cidr": "10.1.0.0/16", "action": "permit"},
            {"cidr": "10.1.5.0/24", "action": "deny"},
            {"cidr": "10.1.20.0/24", "action": "deny"},
        ],
    )
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"}],
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["passed"] is True
    assert payload["violations"] == []
    assert payload["summary"]["ipv4"]["changed_addresses"] == 2 * 2 ** 8


def test_different_kind_entries_that_overlap_return_400(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair
    r = _guard(
        client,
        base_id,
        target_id,
        [
            {"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"},
            {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "none"},
        ],
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["error"] == "invalid_change_guard"
    assert len(body["issues"]) == 1
    assert "must be disjoint" in body["issues"][0]
    assert "#1" in body["issues"][0] and "#2" in body["issues"][0]


def test_equal_actions_are_rejected(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "permit"}],
    )
    # Pydantic shape is fine -> reaches the guard service, which returns 400.
    assert r.status_code == 400
    assert "must differ" in r.json()["issues"][0]


def test_invalid_requests(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair

    # Host bits survive the schema and are rejected by the guard service (400),
    # which lists every offending entry at once.
    r = _guard(
        client,
        base_id,
        target_id,
        [
            {"cidr": "10.0.0.5/24", "from_action": "permit", "to_action": "deny"},
            {"cidr": "10.0.0.0", "from_action": "permit", "to_action": "deny"},
        ],
    )
    assert r.status_code == 400
    issues = r.json()["issues"]
    assert any("invalid CIDR" in i and "10.0.0.5/24" in i for i in issues)
    assert any("explicit prefix length" in i for i in issues)
    assert len(issues) == 2

    # Unknown action string / null action / missing prefix length are
    # schema-level type/value errors -> 422 (Pydantic).
    assert _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.0.0.0/24", "from_action": "maybe", "to_action": "deny"}],
    ).status_code == 422
    assert _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.0.0.0/24", "from_action": "permit", "to_action": None}],
    ).status_code == 422


def test_cross_family_authorization_does_not_cover_change(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "2001:db8::/32", "action": "deny"}])
    target_id = _save(client, [{"cidr": "2001:db8::/32", "action": "permit"}])

    # An IPv4 permit entry cannot authorize the IPv6 flip; no overlap error
    # either, because the families are disjoint.
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "0.0.0.0/0", "from_action": "deny", "to_action": "permit"}],
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["passed"] is False
    v6 = payload["violations"][0]
    assert v6["ip_version"] == 6
    assert v6["change_type"] == "deny_to_permit"
    assert v6["cidrs"] == ["2001:db8::/32"]
    assert v6["unauthorized_address_count"] == 2 ** 96
    assert payload["summary"]["ipv6"]["authorized_addresses"] == 0

    # A matching IPv6 (supernet) entry authorizes it geometrically with the
    # exact 2**96 count — no address enumeration.
    ok = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "::/0", "from_action": "deny", "to_action": "permit"}],
    )
    assert ok.status_code == 200
    assert ok.json()["passed"] is True
    assert ok.json()["summary"]["ipv6"]["authorized_addresses"] == 2 ** 96


def test_ipv6_unauthorized_range_is_minimal(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "2001:db8::/32", "action": "deny"}])
    target_id = _save(client, [{"cidr": "2001:db8::/32", "action": "permit"}])
    # Authorize only one /48; the rest of the /32 is reported minimally.
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "2001:db8:1::/48", "from_action": "deny", "to_action": "permit"}],
    )
    assert r.status_code == 200
    v6 = r.json()["violations"][0]
    assert "2001:db8:1::/48" not in v6["cidrs"]
    assert v6["authorized_address_count"] == 2 ** 80
    assert v6["unauthorized_address_count"] == 2 ** 96 - 2 ** 80
    assert sum(_cidr_count(c) for c in v6["cidrs"]) == v6["unauthorized_address_count"]


def test_no_change_at_all_passes_regardless_of_entries(client: TestClient) -> None:
    # Semantically identical versions (flat permit /8 vs permit /8 + permit /16).
    base_id = _save(
        client,
        [
            {"cidr": "10.0.0.0/8", "action": "permit"},
            {"cidr": "10.1.0.0/16", "action": "permit"},
        ]
    )
    target_id = _save(client, [{"cidr": "10.0.0.0/8", "action": "permit"}])
    # The declared transitions never occur; with no changed addresses there is
    # nothing to violate.
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"}],
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["passed"] is True
    assert payload["violations"] == []
    assert payload["summary"]["total_changed_addresses"] == 0


def test_none_transitions_are_checked(client: TestClient) -> None:
    base_id = _save(client, [{"cidr": "192.0.2.0/24", "action": "permit"}])
    target_id = _save(client, [{"cidr": "198.51.100.0/24", "action": "deny"}])

    # Authorize only the disappearing rule; the new deny range (none->deny)
    # remains unauthorized.
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "192.0.2.0/24", "from_action": "permit", "to_action": "none"}],
    )
    payload = r.json()
    assert payload["passed"] is False
    by_type = {v["change_type"]: v for v in payload["violations"]}
    assert "permit_to_none" not in by_type
    assert by_type["none_to_deny"]["cidrs"] == ["198.51.100.0/24"]
    assert by_type["none_to_deny"]["unauthorized_address_count"] == 2 ** 8

    # Adding the missing entry makes it pass; "none" must be accepted verbatim.
    ok = _guard(
        client,
        base_id,
        target_id,
        [
            {"cidr": "192.0.2.0/24", "from_action": "permit", "to_action": "none"},
            {"cidr": "198.51.100.0/24", "from_action": "none", "to_action": "deny"},
        ],
    )
    assert ok.status_code == 200
    assert ok.json()["passed"] is True


def test_request_shape_errors_are_422(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair
    # Missing authorizations / empty list / extra fields -> 422.
    assert client.post(
        f"/api/analyses/{base_id}/change-guard/{target_id}", json={}
    ).status_code == 422
    assert _guard(client, base_id, target_id, []).status_code == 422
    r = _guard(
        client,
        base_id,
        target_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny", "extra": 1}],
    )
    assert r.status_code == 422


def test_version_lookup_and_id_validation(client: TestClient, nested_pair) -> None:
    base_id, target_id = nested_pair

    assert _guard(
        client, "not-an-id", target_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"}],
    ).status_code == 400
    assert _guard(
        client, base_id, base_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"}],
    ).status_code == 400
    assert _guard(
        client, base_id, "an_0000000000000000",
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"}],
    ).status_code == 404
    assert _guard(
        client, "an_0000000000000000", target_id,
        [{"cidr": "10.0.0.0/8", "from_action": "permit", "to_action": "deny"}],
    ).status_code == 404


def _cidr_count(cidr: str) -> int:
    import ipaddress

    return ipaddress.ip_network(cidr).num_addresses
