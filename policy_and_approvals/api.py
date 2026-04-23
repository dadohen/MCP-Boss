"""HTTP routes for approvals, wired into the existing Starlette app."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

if TYPE_CHECKING:
    from starlette.applications import Starlette
    from .decorator import PolicyGate


def _serialize(obj) -> dict:
    return json.loads(json.dumps(asdict(obj), default=str))


def _caller_identity(request: Request) -> tuple[str, list[str]]:
    """Return (authenticated_email, roles) from the auth middleware scope."""
    state = request.scope.get("state", {}) if hasattr(request, "scope") else {}
    principal = state.get("principal") or "local"
    roles = list(state.get("roles") or [])
    return principal, roles


def _auth_enabled() -> bool:
    return bool(os.environ.get("OAUTH_CLIENT_ID"))


def register_http_routes(app: "Starlette", gate: "PolicyGate") -> None:
    """Append /api/approvals* routes to the given Starlette app."""

    async def list_approvals(request: Request):
        state = request.query_params.get("state", "pending")
        if state == "all":
            items = gate.broker.all()
        else:
            items = [r for r in gate.broker.all() if r.state.value == state]
        return JSONResponse({"count": len(items), "approvals": [_serialize(r) for r in items]})

    async def get_approval(request: Request):
        req = gate.broker.get(request.path_params["approval_id"])
        if not req:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(_serialize(req))

    async def decide_approval(request: Request):
        approval_id = request.path_params["approval_id"]
        decision = request.query_params.get("decision", "")
        decided_by = request.query_params.get("by", "")
        reason = request.query_params.get("reason", "")

        if request.method == "POST":
            try:
                body = await request.json()
                decision = body.get("decision", decision)
                decided_by = body.get("decided_by", decided_by)
                reason = body.get("reason", reason)
            except Exception:
                pass

        # Pull the pending request first so we know which approver roles it requires.
        pending = gate.broker.get(approval_id)
        if pending is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)

        caller_email, caller_roles = _caller_identity(request)
        required_roles = set(pending.policy_decision.approver_groups or [])

        # Authorise the caller. If auth middleware is active (OAUTH_CLIENT_ID set),
        # the caller's mapped roles must intersect the rule's approver groups. If
        # auth is disabled we fall back to 'local' and skip the role check so dev
        # workflows still work.
        if _auth_enabled():
            if not caller_email or caller_email in ("anonymous", "local"):
                return JSONResponse(
                    {"error": "authentication required to decide approvals"},
                    status_code=401,
                )
            if required_roles and not (set(caller_roles) & required_roles):
                return JSONResponse(
                    {
                        "error": "forbidden",
                        "detail": (
                            f"caller {caller_email} lacks any of the required approver "
                            f"roles: {sorted(required_roles)}"
                        ),
                        "caller_roles": caller_roles,
                    },
                    status_code=403,
                )
            # Bind decided_by to the authenticated identity so the audit trail
            # reflects who actually clicked the button, not what the client typed.
            decided_by = caller_email
        elif not decided_by:
            decided_by = "local"

        req = gate.broker.decide(approval_id, decision, decided_by, reason)
        if req is None:
            return JSONResponse(
                {"error": "invalid approval_id or decision value"}, status_code=400
            )
        gate.audit.append(
            "approval_decided",
            invocation_id=req.tool_call.invocation_id,
            actor=req.tool_call.actor,
            tool_name=req.tool_call.tool_name,
            args=req.tool_call.args,
            entities=req.tool_call.entities,
            approval_id=approval_id,
            approval_state=req.state.value,
            decided_by=decided_by,
        )

        # If approved, execute the tool now.
        executed_result = None
        if req.state.value == "approved":
            executed_result = gate.execute_approved(approval_id)

        if request.query_params.get("by") == "gchat":
            # Browser click from Chat card: return a friendly HTML page.
            color = "#0b8043" if req.state.value in ("approved", "executed") else "#c5221f"
            body = f"""<!doctype html><html><head><title>Approval {req.state.value}</title>
<style>body{{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:48px;}}
h1{{color:{color};}} pre{{background:#1e293b;padding:16px;border-radius:8px;overflow:auto;}}</style></head>
<body><h1>Approval {req.state.value.upper()}</h1>
<p><b>Tool:</b> {req.tool_call.tool_name}</p>
<p><b>Decided by:</b> {decided_by}</p>
<p><b>Approval ID:</b> <code>{approval_id}</code></p>
<pre>{json.dumps(executed_result, indent=2, default=str) if executed_result else '(no execution — request was denied)'}</pre>
</body></html>"""
            return HTMLResponse(body)

        return JSONResponse(
            {
                "approval_id": approval_id,
                "state": req.state.value,
                "decided_by": decided_by,
                "executed_result": executed_result,
            }
        )

    async def verify_audit(request: Request):
        ok, bad_seq = gate.audit.verify_chain()
        return JSONResponse(
            {"chain_intact": ok, "broken_at_seq": bad_seq, "audit_path": str(gate.audit.path)}
        )

    new_routes = [
        Route("/api/approvals", endpoint=list_approvals, methods=["GET"]),
        Route("/api/approvals/{approval_id}", endpoint=get_approval, methods=["GET"]),
        Route(
            "/api/approvals/{approval_id}/decide",
            endpoint=decide_approval,
            methods=["GET", "POST"],
        ),
        Route("/api/audit/verify", endpoint=verify_audit, methods=["GET"]),
    ]

    # Insert before the static-file catch-all Mount so the new routes take
    # priority. Starlette normalises Mount("/") to path="" — match by class +
    # empty/'/'  path so the lookup actually finds it.
    existing = list(app.routes)
    static_mount_idx = next(
        (
            i
            for i, r in enumerate(existing)
            if r.__class__.__name__ == "Mount" and getattr(r, "path", "") in ("", "/")
        ),
        len(existing),
    )
    existing[static_mount_idx:static_mount_idx] = new_routes
    app.router.routes = existing
