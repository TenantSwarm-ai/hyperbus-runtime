"""Identity map: the local file that binds verified credentials to ``agent_id``.

Spec 003 §5 and US-3. The engine loads this file and never fetches it from a
remote service (VII.3). The cloud inventory generates it; the engine validates
and enforces it. Validation is strict: unknown keys, duplicate YAML keys, and
any identity that could match two agents are rejected at load time.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SPIFFE_SCHEME = "spiffe://"
IDENTITY_TYPES = frozenset({"spiffe", "jwt"})
ALLOWED_JWT_ALGORITHMS = frozenset({"RS256", "ES256"})

_TOP_LEVEL_KEYS = frozenset({"tenant_id", "change_ref", "verifiers", "agents"})
_VERIFIER_KEYS = frozenset({"jwt", "spiffe"})
_JWT_ISSUER_KEYS = frozenset(
    {
        "issuer",
        "audience",
        "jwks_url",
        "jwks_file",
        "algorithms",
        "leeway_seconds",
        "max_age_seconds",
    }
)
_SPIFFE_KEYS = frozenset({"trust_domain"})
_AGENT_KEYS = frozenset({"identities", "unix_uids"})
_IDENTITY_KEYS = {
    "spiffe": frozenset({"type", "match"}),
    "jwt": frozenset({"type", "match", "issuer", "claim"}),
}
_TRUST_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# A SPIFFE literal must name a trust domain and at least one path segment, so
# ``spiffe://acme.example/*`` (every identity in the domain) is rejected.
_SPIFFE_PATH_RE = re.compile(r"^spiffe://[^/*]+/.+")
_DEFAULT_LEEWAY = 60
_MAX_LEEWAY = 60  # AC-4.1: clock skew of at most 60 s
_DEFAULT_MAX_AGE = 3600
_MIN_MAX_AGE = 60
_MAX_MAX_AGE = 86400


class IdentityMapError(ValueError):
    """The identity map failed validation. The engine must not serve with it."""


class IdentityDenied(PermissionError):
    """One request failed identity verification. ``reason`` is a stable code.

    Subclasses ``PermissionError`` so the RPC layer maps it to the same error
    type clients already handle for capability denials.
    """

    def __init__(
        self,
        reason: str,
        *,
        http_status: int = 401,
        identity: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.identity = identity


@dataclass(frozen=True)
class IdentityRule:
    """One credential identity that maps to an agent."""

    type: str
    match: str
    issuer: str | None = None
    claim: str | None = None

    @property
    def is_prefix(self) -> bool:
        return self.match.endswith("*")

    @property
    def literal(self) -> str:
        return self.match[:-1] if self.is_prefix else self.match

    def matches(self, value: str) -> bool:
        if self.is_prefix:
            return value.startswith(self.literal)
        return value == self.match

    def overlaps(self, other: IdentityRule) -> bool:
        """True if some credential value could match both rules."""
        if self.type != other.type:
            return False
        if self.type == "jwt" and (self.issuer, self.claim) != (other.issuer, other.claim):
            return False
        if self.is_prefix and other.is_prefix:
            return self.literal.startswith(other.literal) or other.literal.startswith(
                self.literal
            )
        if self.is_prefix:
            return other.match.startswith(self.literal)
        if other.is_prefix:
            return self.match.startswith(other.literal)
        return self.match == other.match


@dataclass(frozen=True)
class AgentBinding:
    agent_id: str
    identities: tuple[IdentityRule, ...] = ()
    unix_uids: frozenset[int] = frozenset()

    @property
    def blocked(self) -> bool:
        """An agent with no identities and no uids loads, but nothing reaches it."""
        return not self.identities and not self.unix_uids


@dataclass(frozen=True)
class JwtIssuerConfig:
    issuer: str
    audience: str
    jwks_url: str | None
    jwks_file: str | None
    algorithms: tuple[str, ...]
    leeway_seconds: int
    max_age_seconds: int


@dataclass(frozen=True)
class SpiffeConfig:
    trust_domain: str


@dataclass(frozen=True)
class IdentityMap:
    tenant_id: str
    digest: str
    agents: Mapping[str, AgentBinding]
    jwt_issuers: Mapping[str, JwtIssuerConfig]
    spiffe: SpiffeConfig | None = None
    change_ref: str | None = None

    def agents_for_spiffe(self, spiffe_id: str) -> set[str]:
        return {
            binding.agent_id
            for binding in self.agents.values()
            for rule in binding.identities
            if rule.type == "spiffe" and rule.matches(spiffe_id)
        }

    def agents_for_jwt(self, issuer: str, claims: Mapping[str, Any]) -> set[str]:
        found: set[str] = set()
        for binding in self.agents.values():
            for rule in binding.identities:
                if rule.type != "jwt" or rule.issuer != issuer or rule.claim is None:
                    continue
                value = claims.get(rule.claim)
                if isinstance(value, str) and rule.matches(value):
                    found.add(binding.agent_id)
        return found

    def agent_for_uid(self, uid: int) -> str | None:
        for binding in self.agents.values():
            if uid in binding.unix_uids:
                return binding.agent_id
        return None

    def summary(self) -> dict[str, dict[str, Any]]:
        return {
            agent_id: {
                "identities": len(binding.identities),
                "unix_uids": len(binding.unix_uids),
                "blocked": binding.blocked,
            }
            for agent_id, binding in sorted(self.agents.items())
        }


class _UniqueKeyLoader(yaml.SafeLoader):
    """Rejects duplicate mapping keys instead of silently keeping the last one."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,  # noqa: FBT001, FBT002 - yaml constructor signature
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            msg = f"duplicate key {key!r} in identity map"
            raise yaml.constructor.ConstructorError(
                None, None, msg, key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_identity_map(
    path: str | Path,
    *,
    expected_tenant_id: str | None = None,
) -> IdentityMap:
    """Read and validate the identity map file."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        msg = f"identity map unreadable: {exc}"
        raise IdentityMapError(msg) from exc
    return parse_identity_map(data, expected_tenant_id=expected_tenant_id)


def parse_identity_map(
    data: bytes,
    *,
    expected_tenant_id: str | None = None,
) -> IdentityMap:
    """Validate identity map bytes. The digest covers the exact bytes loaded."""
    digest = hashlib.sha256(data).hexdigest()
    try:
        raw = yaml.load(data.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except (UnicodeDecodeError, yaml.YAMLError, TypeError) as exc:
        msg = f"identity map is not valid YAML: {exc}"
        raise IdentityMapError(msg) from exc
    if not isinstance(raw, dict):
        msg = "identity map must be a mapping"
        raise IdentityMapError(msg)
    _reject_unknown(raw, _TOP_LEVEL_KEYS, "identity map")

    tenant_id = _require_str(raw, "tenant_id", "identity map")
    if expected_tenant_id is not None and tenant_id != expected_tenant_id:
        msg = (
            f"identity map tenant {tenant_id!r} != engine tenant {expected_tenant_id!r}"
        )
        raise IdentityMapError(msg)
    change_ref = _optional_str(raw, "change_ref", "identity map")

    jwt_issuers, spiffe = _parse_verifiers(raw.get("verifiers"))
    agents = _parse_agents(raw.get("agents"), jwt_issuers=jwt_issuers, spiffe=spiffe)
    _reject_cross_agent_overlaps(agents)
    return IdentityMap(
        tenant_id=tenant_id,
        digest=digest,
        agents=agents,
        jwt_issuers=jwt_issuers,
        spiffe=spiffe,
        change_ref=change_ref,
    )


def _parse_verifiers(
    raw: Any,
) -> tuple[dict[str, JwtIssuerConfig], SpiffeConfig | None]:
    if raw is None:
        return {}, None
    if not isinstance(raw, dict):
        msg = "verifiers must be a mapping"
        raise IdentityMapError(msg)
    _reject_unknown(raw, _VERIFIER_KEYS, "verifiers")
    issuers: dict[str, JwtIssuerConfig] = {}
    for entry in _as_list(raw.get("jwt"), "verifiers.jwt"):
        config = _parse_jwt_issuer(entry)
        if config.issuer in issuers:
            msg = f"verifiers.jwt lists issuer {config.issuer!r} twice"
            raise IdentityMapError(msg)
        issuers[config.issuer] = config
    spiffe = None
    if raw.get("spiffe") is not None:
        spiffe = _parse_spiffe(raw["spiffe"])
    return issuers, spiffe


def _parse_jwt_issuer(entry: Any) -> JwtIssuerConfig:
    if not isinstance(entry, dict):
        msg = "each verifiers.jwt entry must be a mapping"
        raise IdentityMapError(msg)
    _reject_unknown(entry, _JWT_ISSUER_KEYS, "verifiers.jwt entry")
    issuer = _require_str(entry, "issuer", "verifiers.jwt entry")
    audience = _require_str(entry, "audience", "verifiers.jwt entry")
    jwks_url = _optional_str(entry, "jwks_url", "verifiers.jwt entry")
    jwks_file = _optional_str(entry, "jwks_file", "verifiers.jwt entry")
    if (jwks_url is None) == (jwks_file is None):
        msg = f"verifier {issuer!r}: set exactly one of jwks_url or jwks_file"
        raise IdentityMapError(msg)
    if jwks_url is not None and not jwks_url.startswith("https://"):
        msg = f"verifier {issuer!r}: jwks_url must use https"
        raise IdentityMapError(msg)
    algorithms = _parse_algorithms(issuer, entry.get("algorithms"))
    leeway = _int_in_range(entry, "leeway_seconds", _DEFAULT_LEEWAY, 0, _MAX_LEEWAY)
    max_age = _int_in_range(
        entry, "max_age_seconds", _DEFAULT_MAX_AGE, _MIN_MAX_AGE, _MAX_MAX_AGE
    )
    return JwtIssuerConfig(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        jwks_file=jwks_file,
        algorithms=algorithms,
        leeway_seconds=leeway,
        max_age_seconds=max_age,
    )


def _parse_algorithms(issuer: str, raw: Any) -> tuple[str, ...]:
    if raw is None:
        return tuple(sorted(ALLOWED_JWT_ALGORITHMS))
    if not isinstance(raw, list) or not raw:
        msg = f"verifier {issuer!r}: algorithms must be a non-empty list"
        raise IdentityMapError(msg)
    for alg in raw:
        if alg not in ALLOWED_JWT_ALGORITHMS:
            msg = (
                f"verifier {issuer!r}: algorithm {alg!r} is not allowed; "
                f"use one of {sorted(ALLOWED_JWT_ALGORITHMS)}"
            )
            raise IdentityMapError(msg)
    return tuple(dict.fromkeys(raw))


def _parse_spiffe(raw: Any) -> SpiffeConfig:
    if not isinstance(raw, dict):
        msg = "verifiers.spiffe must be a mapping"
        raise IdentityMapError(msg)
    _reject_unknown(raw, _SPIFFE_KEYS, "verifiers.spiffe")
    trust_domain = _require_str(raw, "trust_domain", "verifiers.spiffe")
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        msg = f"verifiers.spiffe.trust_domain {trust_domain!r} is not a valid domain"
        raise IdentityMapError(msg)
    return SpiffeConfig(trust_domain=trust_domain)


def _parse_agents(
    raw: Any,
    *,
    jwt_issuers: Mapping[str, JwtIssuerConfig],
    spiffe: SpiffeConfig | None,
) -> dict[str, AgentBinding]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        msg = "agents must be a mapping of agent_id to binding"
        raise IdentityMapError(msg)
    agents: dict[str, AgentBinding] = {}
    for agent_id, entry in raw.items():
        if not isinstance(agent_id, str) or not agent_id.strip():
            msg = "agent_id keys must be non-empty strings"
            raise IdentityMapError(msg)
        where = f"agents.{agent_id}"
        body: Any = {} if entry is None else entry
        if not isinstance(body, dict):
            msg = f"{where} must be a mapping"
            raise IdentityMapError(msg)
        _reject_unknown(body, _AGENT_KEYS, where)
        identities = tuple(
            _parse_identity(where, item, jwt_issuers=jwt_issuers, spiffe=spiffe)
            for item in _as_list(body.get("identities"), f"{where}.identities")
        )
        agents[agent_id] = AgentBinding(
            agent_id=agent_id,
            identities=identities,
            unix_uids=_parse_uids(where, body.get("unix_uids")),
        )
    return agents


def _parse_identity(
    where: str,
    item: Any,
    *,
    jwt_issuers: Mapping[str, JwtIssuerConfig],
    spiffe: SpiffeConfig | None,
) -> IdentityRule:
    if not isinstance(item, dict):
        msg = f"{where}: each identity must be a mapping"
        raise IdentityMapError(msg)
    kind = item.get("type")
    if kind not in IDENTITY_TYPES:
        msg = f"{where}: identity type must be one of {sorted(IDENTITY_TYPES)}"
        raise IdentityMapError(msg)
    _reject_unknown(item, _IDENTITY_KEYS[kind], f"{where} {kind} identity")
    match = _require_str(item, "match", f"{where} {kind} identity")
    _validate_match(where, match)

    if kind == "spiffe":
        if spiffe is None:
            msg = f"{where}: spiffe identity requires verifiers.spiffe"
            raise IdentityMapError(msg)
        if not match.startswith(f"{SPIFFE_SCHEME}{spiffe.trust_domain}/"):
            msg = f"{where}: {match!r} is outside trust domain {spiffe.trust_domain!r}"
            raise IdentityMapError(msg)
        literal = match[:-1] if match.endswith("*") else match
        if not _SPIFFE_PATH_RE.match(literal):
            msg = f"{where}: spiffe match {match!r} needs a path after the trust domain"
            raise IdentityMapError(msg)
        return IdentityRule(type="spiffe", match=match)

    issuer = _require_str(item, "issuer", f"{where} jwt identity")
    claim = _require_str(item, "claim", f"{where} jwt identity")
    if issuer not in jwt_issuers:
        msg = f"{where}: issuer {issuer!r} is not configured under verifiers.jwt"
        raise IdentityMapError(msg)
    return IdentityRule(type="jwt", match=match, issuer=issuer, claim=claim)


def _validate_match(where: str, match: str) -> None:
    if match.count("*") > 1 or ("*" in match and not match.endswith("*")):
        msg = f"{where}: a wildcard is allowed only as one trailing '*'"
        raise IdentityMapError(msg)
    literal = match[:-1] if match.endswith("*") else match
    if not literal:
        msg = f"{where}: match must not be empty or a bare '*'"
        raise IdentityMapError(msg)


def _parse_uids(where: str, raw: Any) -> frozenset[int]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        msg = f"{where}.unix_uids must be a list"
        raise IdentityMapError(msg)
    uids: set[int] = set()
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            msg = f"{where}.unix_uids entries must be non-negative integers"
            raise IdentityMapError(msg)
        uids.add(value)
    return frozenset(uids)


def _reject_cross_agent_overlaps(agents: Mapping[str, AgentBinding]) -> None:
    bindings = list(agents.values())
    for index, first in enumerate(bindings):
        for second in bindings[index + 1 :]:
            for rule_a in first.identities:
                for rule_b in second.identities:
                    if rule_a.overlaps(rule_b):
                        msg = (
                            f"identity {rule_a.match!r} for {first.agent_id!r} "
                            f"overlaps {rule_b.match!r} for {second.agent_id!r}"
                        )
                        raise IdentityMapError(msg)
            shared = first.unix_uids & second.unix_uids
            if shared:
                msg = (
                    f"unix uid(s) {sorted(shared)} map to both "
                    f"{first.agent_id!r} and {second.agent_id!r}"
                )
                raise IdentityMapError(msg)


def _reject_unknown(mapping: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(str(key) for key in mapping if key not in allowed)
    if unknown:
        msg = f"unknown key(s) in {where}: {', '.join(unknown)}"
        raise IdentityMapError(msg)


def _require_str(mapping: Mapping[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        msg = f"{where}: {key} must be a non-empty string"
        raise IdentityMapError(msg)
    return value


def _optional_str(mapping: Mapping[str, Any], key: str, where: str) -> str | None:
    if mapping.get(key) is None:
        return None
    return _require_str(mapping, key, where)


def _as_list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        msg = f"{where} must be a list"
        raise IdentityMapError(msg)
    return value


def _int_in_range(mapping: Mapping[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = mapping.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        msg = f"{key} must be an integer between {low} and {high}"
        raise IdentityMapError(msg)
    return value
