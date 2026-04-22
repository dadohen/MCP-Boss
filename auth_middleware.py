"""Authentication middleware for MCP Boss.

Pattern mirrors the YaraL-Validator-MCP `_verify_google_token` helper: when the
environment variable OAUTH_CLIENT_ID is set, every incoming HTTP request must
present a valid Google OIDC ID token whose `aud` matches that client ID. When
OAUTH_CLIENT_ID is unset we skip verification entirely so local development and
`pytest` workflows still work.

Beyond the binary "is the caller authenticated" check, this module also loads a
role map (YAML or JSON dict) that binds a caller's e-mail (or domain) to one or
more approver role names used by policy_and_approvals/policies.yaml:
    security-oncall, soc-manager, identity-team, cloud-platform,
    detection-engineering, legal, security-leadership.

The authenticated principal and their roles are attached to the request scope
under `scope["state"]["principal"]` and `scope["state"]["roles"]` so downstream
routes (approval decide, session store, policy gate) can use them.

Environment variables:
    OAUTH_CLIENT_ID           Google OAuth client ID the ID token must target.
                              If unset, auth is disabled and every request is
                              tagged with principal="local" and no roles.
    ALLOWED_EMAILS            Optional comma-separated allowlist. If set, any
                              authenticated email not in the list is rejected.
    ROLE_MAP_PATH             Optional path to a YAML file of the form:
                                  roles:
                                    alice@company.com: [security-oncall]
                                    "@company.com":    [soc-manager]
    ROLE_MAP_JSON             Optional inline JSON string, same shape as the
                              `roles` block above. Takes precedence over
                              ROLE_MAP_PATH.
    AUTH_EXEMPT_PATHS         Optional comma-separated list of path prefixes
                              that bypass auth (default: /health,/static,/).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("mcp-boss.auth")

LOCAL_PRINCIPAL = "local"

# Approver role names recognised by policy_and_approvals/policies.yaml.
KNOWN_ROLES = {
    "security-oncall",
    "soc-manager",
    "identity-team",
    "cloud-platform",
    "detection-engineering",
    "legal",
    "security-leadership",
}

_DEFAULT_EXEMPT_PREFIXES: Tuple[str, ...] = (
    "/health",
    "/static",
)


def _load_role_map() -> Dict[str, List[str]]:
    """Load e-mail (or @domain) -> [role, ...] map from env or file."""
    raw_json = os.environ.get("ROLE_MAP_JSON", "").strip()
    if raw_json:
        try:
            data = json.loads(raw_json)
            return {str(k): list(v) for k, v in data.items()}
        except Exception as exc:
            logger.error("ROLE_MAP_JSON is not valid JSON: %s", exc)
            return {}

    path = os.environ.get("ROLE_MAP_PATH", "").strip()
    if not path or not os.path.exists(path):
        return {}
    try:
        import yaml

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        roles = data.get("roles", {}) if isinstance(data, dict) else {}
        return {str(k): list(v) for k, v in roles.items()}
    except Exception as exc:
        logger.error("Failed to load ROLE_MAP_PATH=%s: %s", path, exc)
        return {}


_ROLE_MAP: Dict[str, List[str]] = _load_role_map()


def roles_for_email(email: str) -> List[str]:
    """Return the union of roles for a given authenticated e-mail.

    Resolution order:
        1. Exact match on the e-mail.
        2. Any key starting with '@' that matches the e-mail's domain.
    """
    if not email:
        return []
    out: List[str] = []
    exact = _ROLE_MAP.get(email, [])
    out.extend(exact)
    if "@" in email:
        domain = "@" + email.split("@", 1)[1].lower()
        for key, vals in _ROLE_MAP.items():
            if key.startswith("@") and key.lower() == domain:
                out.extend(vals)
    # Deduplicate while preserving order.
    seen: set = set()
    unique: List[str] = []
    for r in out:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def _exempt_prefixes() -> Tuple[str, ...]:
    raw = os.environ.get("AUTH_EXEMPT_PATHS", "")
    if not raw:
        return _DEFAULT_EXEMPT_PREFIXES
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def _allowed_emails() -> set:
    raw = os.environ.get("ALLOWED_EMAILS", "")
    return {e.strip() for e in raw.split(",") if e.strip()}


def _accepted_audiences(primary: str) -> List[str]:
    """Primary client ID plus any extras from OAUTH_ADDITIONAL_AUDIENCES.

    Lets CI / service-to-service callers present a token with aud=<service URL>
    or aud=<gcloud default client> without losing the tight audience check for
    browser flows. Every candidate still runs through signature verification
    and the ALLOWED_EMAILS filter, so multi-audience does not relax auth; it
    only widens which token shapes are accepted.
    """
    extras_raw = os.environ.get("OAUTH_ADDITIONAL_AUDIENCES", "")
    extras = [a.strip() for a in extras_raw.split(",") if a.strip()]
    seen: set = set()
    out: List[str] = []
    for a in [primary, *extras]:
        if a and a not in seen:
            seen.add(a)
            out.append(a)
    return out


def verify_google_id_token(bearer: str, audience: str) -> Optional[Dict[str, str]]:
    """Verify a Google OIDC ID token against the primary audience plus any
    listed in OAUTH_ADDITIONAL_AUDIENCES. Returns {'email': ..., 'sub': ...}
    on the first match, or None."""
    try:
        from google.oauth2 import id_token as gid
        from google.auth.transport import requests as gr
    except Exception as exc:
        logger.warning("google-auth not available: %s", exc)
        return None

    transport = gr.Request()
    last_exc: Exception | None = None
    for candidate in _accepted_audiences(audience):
        try:
            info = gid.verify_oauth2_token(bearer, transport, candidate)
            email = info.get("email", "")
            sub = info.get("sub", "")
            if not email:
                return None
            return {"email": email, "sub": sub}
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc is not None:
        logger.warning("ID token verification failed against all audiences: %s", last_exc)
    return None


class AuthMiddleware:
    """ASGI middleware that enforces Google ID-token auth when OAUTH_CLIENT_ID is set.

    The authenticated principal (email) and their mapped roles are stashed in
    `scope["state"]["principal"]` and `scope["state"]["roles"]`. When auth is
    disabled, principal defaults to 'local' with no roles.
    """

    def __init__(self, app, client_id: Optional[str] = None):
        self.app = app
        self.client_id = client_id if client_id is not None else os.environ.get("OAUTH_CLIENT_ID", "")
        self.exempt = _exempt_prefixes()
        self.allowed = _allowed_emails()
        _boot_safety_check(self.client_id)


def _boot_safety_check(client_id: str) -> None:
    """Prevent the "auth off + all roles granted" combo from shipping to prod.

    If LOCAL_DEV_ALL_ROLES=1 is set but OAUTH_CLIENT_ID is unset, abort unless
    the operator explicitly acknowledges it is a dev machine via
    MCP_BOSS_ENV=dev. This stops a staging or prod deploy from becoming an
    open bar where every request is auto-approved as every role.
    """
    all_roles = os.environ.get("LOCAL_DEV_ALL_ROLES") == "1"
    if not client_id and all_roles:
        env = os.environ.get("MCP_BOSS_ENV", "").lower()
        if env != "dev":
            raise RuntimeError(
                "Refusing to start: LOCAL_DEV_ALL_ROLES=1 with no OAUTH_CLIENT_ID. "
                "This combination disables auth AND grants every request every "
                "approver role. Set MCP_BOSS_ENV=dev on your local machine, or "
                "set OAUTH_CLIENT_ID for any non-dev deploy."
            )
        logger.warning(
            "AuthMiddleware: OAUTH_CLIENT_ID unset and LOCAL_DEV_ALL_ROLES=1. "
            "Running in dev mode with auth disabled and all approver roles granted."
        )
    elif not client_id:
        logger.warning(
            "AuthMiddleware: OAUTH_CLIENT_ID unset. Auth is disabled, approval "
            "role checks are skipped, and every request shows as principal=local. "
            "Do not ship this configuration outside local development."
        )

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "") or ""

        # Set up state dict so downstream code can read it.
        state = scope.setdefault("state", {})

        # Local dev / auth disabled: stamp a 'local' principal and pass through.
        if not self.client_id:
            state["principal"] = LOCAL_PRINCIPAL
            state["roles"] = list(KNOWN_ROLES) if os.environ.get("LOCAL_DEV_ALL_ROLES") == "1" else []
            await self.app(scope, receive, send)
            return

        # Exempt paths (health check, static assets) bypass auth.
        for prefix in self.exempt:
            if path.startswith(prefix):
                state["principal"] = "anonymous"
                state["roles"] = []
                await self.app(scope, receive, send)
                return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            await _send_401(send, "missing bearer token")
            return

        info = verify_google_id_token(auth_header[len("Bearer "):], self.client_id)
        if not info:
            await _send_401(send, "invalid or expired token")
            return

        email = info["email"]
        if self.allowed and email not in self.allowed:
            await _send_403(send, "email not in ALLOWED_EMAILS")
            return

        state["principal"] = email
        state["roles"] = roles_for_email(email)
        await self.app(scope, receive, send)


async def _send_401(send, detail: str) -> None:
    body = json.dumps({"error": "unauthorized", "detail": detail}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")],
    })
    await send({"type": "http.response.body", "body": body})


async def _send_403(send, detail: str) -> None:
    body = json.dumps({"error": "forbidden", "detail": detail}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": body})


def principal_from_request(request) -> str:
    """Return the authenticated principal email, or 'local' in dev mode."""
    try:
        return request.scope.get("state", {}).get("principal") or LOCAL_PRINCIPAL
    except Exception:
        return LOCAL_PRINCIPAL


def roles_from_request(request) -> List[str]:
    try:
        return list(request.scope.get("state", {}).get("roles") or [])
    except Exception:
        return []


def caller_has_any_role(request, required: Iterable[str]) -> bool:
    """True if the authenticated caller's roles intersect `required`.

    When OAUTH_CLIENT_ID is unset (dev mode) this returns True so local testing
    still works. Production deployments should always set OAUTH_CLIENT_ID.
    """
    if not os.environ.get("OAUTH_CLIENT_ID"):
        return True
    caller_roles = set(roles_from_request(request))
    required_set = set(required)
    if not required_set:
        return True
    return bool(caller_roles & required_set)
