"""
Automated SOC MCP Server — Full Security Operations Suite
===========================================================
The complete autonomous security operations toolkit bridging every Google Cloud
Security pillar plus third-party containment APIs into a single MCP endpoint.

SecOps tools now use SecOpsClient library for reliable authentication.

TOOL CATEGORIES:
  🔍 DISCOVERY & HUNTING (read-only)
    - get_scc_findings          → Security Command Center vulnerabilities (any state/severity)
    - list_scc_findings_custom  → Query SCC with custom filters
    - get_scc_finding_details   → Get detailed finding info
    - query_cloud_logging       → Cloud Audit Logs
    - search_secops_udm         → Chronicle UDM / YARA-L search
    - list_secops_detections    → YARA-L detection alerts
    - check_ingestion_health    → Unparsed log monitoring

  🧠 INTELLIGENCE & ENRICHMENT
    - enrich_indicator          → GTI / VirusTotal (IP, domain, hash, URL)
    - extract_iocs_from_detections → Bulk IOC extraction from detection alerts
    - vertex_ai_investigate     → Gemini-powered threat analysis

  📋 DATA TABLE MANAGEMENT (SecOps)
    - list_data_tables          → List all Data Tables
    - get_data_table            → Read a Data Table's contents
    - update_data_table         → Overwrite/append rows to a Data Table

  🛡️ DETECTION MANAGEMENT (SecOps)
    - list_rules                → List YARA-L rules and their status
    - toggle_rule               → Enable or disable a YARA-L rule

  📧 EMAIL CONTAINMENT (Microsoft Graph)
    - purge_email_o365          → Hard Delete email from all inboxes by Message-ID

  🔑 IDENTITY CONTAINMENT
    - suspend_okta_user         → Suspend user + clear sessions in Okta
    - revoke_azure_ad_sessions  → Revoke all sign-in sessions in Azure AD / Entra ID

  ☁️ CLOUD CREDENTIAL CONTAINMENT
    - revoke_aws_access_keys    → Disable all active AWS IAM access keys
    - revoke_aws_sts_sessions   → Deny all pre-existing STS assumed-role sessions
    - revoke_gcp_sa_keys        → Delete all user-managed GCP service account keys

  🖥️ ENDPOINT CONTAINMENT
    - isolate_crowdstrike_host  → Network-isolate a host via CrowdStrike Falcon

  📂 SOAR CASE MANAGEMENT
    - create_soar_case          → Create a new SOAR case
    - update_soar_case          → Update priority, add comments, close a case

  🔎 NATURAL LANGUAGE SEARCH & ALERTS (SecOps)
    - search_security_events    → NL-to-UDM search via Gemini
    - get_security_alerts       → Recent security alerts
    - lookup_entity             → Entity risk score & context

  🦠 GTI / VIRUSTOTAL DEEP REPORTS
    - get_file_report           → Full file analysis by hash
    - get_domain_report         → Domain reputation & DNS
    - get_ip_report             → IP ASN, country, reputation
    - search_threat_actors      → Threat actor intelligence search
    - search_malware_families   → Malware family intelligence search

  📋 DETECTION RULE GENERATION
    - create_detection_rule_for_scc_finding → Auto-generate YARA-L rules from SCC findings

  🛡️ SCC VULNERABILITY & REMEDIATION
    - top_vulnerability_findings → Vulns sorted by Attack Exposure Score
    - get_finding_remediation   → Remediation guidance for a finding

  📒 SOAR PLAYBOOK MANAGEMENT
    - list_playbooks            → List all SOAR playbooks
    - get_playbook              → Get playbook details
    - create_playbook           → Create a new SOAR playbook
    - create_containment_playbook → Pre-built containment playbook templates

  📂 SOAR CASES & ALERTS (Extended)
    - list_cases                → List all SOAR cases
    - get_case_alerts           → Alerts for a specific case
    - add_case_comment          → Add comment to a case

  📜 CLOUD LOGGING (v2 API)
    - list_log_entries          → Query logs using Log Query Language
    - list_log_names            → Discover available log sources
    - list_log_buckets          → Log storage buckets & retention
    - get_log_bucket            → Specific bucket details
    - list_log_views            → Log views within a bucket
    - query_secops_audit_logs   → SecOps SIEM/SOAR audit log queries

Deployed as a single Docker container on Cloud Run.
Auth: Workload Identity + ADC. Zero embedded secrets.

  🔐 RBAC & ACCESS CONTROL
    - list_data_access_labels  → Data access labels (RBAC)
    - list_data_access_scopes  → Data access scopes (RBAC)

  🔧 PARSERS & PARSING
    - list_parsers              → Configured parsers and log types
    - validate_parser           → Test parser against raw log sample

  📡 FEEDS & INGESTION
    - list_feeds                → Configured data feeds
    - get_feed                  → Specific feed details

  📊 INGESTION METRICS
    - query_ingestion_stats     → Ingestion volume by product/source

  🛡️ RULE MANAGEMENT (expanded)
    - create_rule               → Create a YARA-L detection rule
    - get_rule                  → Get specific rule details
    - list_rule_errors          → Rule deployment errors

  📂 CASE MANAGEMENT (expanded)
    - list_case_comments        → Comments for a SOAR case
    - update_case_priority      → Update case priority
    - close_case                → Close a SOAR case

  📈 DASHBOARDS / OVERVIEW
    - get_case_overview         → Case overview dashboard data

  🤖 AUTONOMOUS INVESTIGATION
    - autonomous_investigate     → End-to-end: enrich → search → assess → detect → respond → report

🔗 OFFICIAL GOOGLE MCP SERVER WRAPPERS (15 new tools)
  SecOps MCP (10):
    - secops_list_cases         → List all cases from official SecOps MCP
    - secops_get_case           → Get case details
    - secops_update_case        → Update case priority/status/comments
    - secops_list_case_alerts   → List case alerts
    - secops_get_case_alert     → Get alert details
    - secops_update_case_alert  → Update alert status/severity
    - secops_create_case_comment → Add comment to case
    - secops_list_case_comments → List case comments
    - secops_execute_bulk_close_case → Bulk close cases
    - secops_execute_manual_action → Execute custom SOAR actions
  
  BigQuery MCP (5):
    - bigquery_list_dataset_ids  → List BigQuery datasets
    - bigquery_list_table_ids    → List tables in dataset
    - bigquery_get_dataset_info  → Get dataset schema/metadata
    - bigquery_get_table_info    → Get table schema/metadata
    - bigquery_execute_sql       → Execute SQL query in BigQuery

76 tools total (61 custom + 10 SecOps MCP + 5 BigQuery MCP).

Author: David Adohen
"""

import os
import json
import logging
import re
import requests
import asyncio
import google.auth
from google.auth.transport.requests import Request as GCPRequest
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from secops import SecOpsClient
from google.cloud import securitycenter
from google.cloud import logging as cloud_logging
from google.api_core.exceptions import (
    GoogleAPICallError,
    PermissionDenied,
    NotFound,
    ResourceExhausted,
)
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta, timezone
import uuid

# ═══════════════════════════════════════════════════════════════
# SESSION MEMORY (In-Memory Store)
# ═══════════════════════════════════════════════════════════════

class SessionMemory:
    """Store context/state and conversation history for a session."""
    def __init__(self):
        self.sessions = {}
    
    def create_session(self):
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'created': datetime.now(timezone.utc),
            'last_case_id': None,
            'last_alert_id': None,
            'last_ip': None,
            'last_user': None,
            'last_domain': None,
            'investigation_notes': [],
            'context': {},
            'chat_history': [],  # List of {role, parts} for multi-turn
        }
        return session_id
    
    def get_session(self, session_id):
        return self.sessions.get(session_id)
    
    def get_or_create(self, session_id: str) -> dict:
        """Get existing session or create new one with given ID."""
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                'created': datetime.now(timezone.utc),
                'last_case_id': None,
                'last_alert_id': None,
                'last_ip': None,
                'last_user': None,
                'last_domain': None,
                'investigation_notes': [],
                'context': {},
                'chat_history': [],
            }
        return self.sessions[session_id]
    
    def append_history(self, session_id: str, role: str, text: str):
        """Append a turn to chat history (role: 'user' or 'model')."""
        session = self.get_or_create(session_id)
        session['chat_history'].append({'role': role, 'parts': [{'text': text}]})
        # Keep last 20 turns to avoid token bloat
        if len(session['chat_history']) > 20:
            session['chat_history'] = session['chat_history'][-20:]

    def get_history(self, session_id: str) -> list:
        """Get conversation history for a session."""
        session = self.sessions.get(session_id)
        return session['chat_history'] if session else []

    def clear_history(self, session_id: str):
        """Clear conversation history for a session."""
        if session_id in self.sessions:
            self.sessions[session_id]['chat_history'] = []

    def update_session(self, session_id, key, value):
        if session_id in self.sessions:
            self.sessions[session_id][key] = value
    
    def add_note(self, session_id, note):
        if session_id in self.sessions:
            self.sessions[session_id]['investigation_notes'].append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'note': note
            })

session_store = SessionMemory()

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

SECOPS_PROJECT_ID = os.getenv("SECOPS_PROJECT_ID", "YOUR_PROJECT_ID")
SECOPS_CUSTOMER_ID = os.getenv("SECOPS_CUSTOMER_ID", "YOUR_CUSTOMER_ID")
SECOPS_REGION = os.getenv("SECOPS_REGION", "us")
GTI_API_KEY = os.getenv("GTI_API_KEY", "")

# Third-party integration keys (stored in Secret Manager)
O365_CLIENT_ID = os.getenv("O365_CLIENT_ID", "")
O365_CLIENT_SECRET = os.getenv("O365_CLIENT_SECRET", "")
O365_TENANT_ID = os.getenv("O365_TENANT_ID", "")
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "")
AZURE_AD_TENANT_ID = os.getenv("AZURE_AD_TENANT_ID", "")
AZURE_AD_CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID", "")
AZURE_AD_CLIENT_SECRET = os.getenv("AZURE_AD_CLIENT_SECRET", "")
AWS_ACCESS_KEY_ID = os.getenv("SOAR_AWS_KEY", "")
AWS_SECRET_ACCESS_KEY = os.getenv("SOAR_AWS_SECRET", "")
CS_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
CS_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
CS_BASE_URL = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
CLAUDE_REGION = os.getenv("CLAUDE_REGION", "global")
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
ALLOWED_EMAILS = set(e.strip() for e in os.getenv("ALLOWED_EMAILS", "carter@linus.joonix.net,dnehoda@gmail.com").split(",") if e.strip())

SECOPS_BASE_URL = (
    f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1alpha"
    f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
    f"/instances/{SECOPS_CUSTOMER_ID}"
)

# ── Siemplify SOAR (pre-migration to Google SecOps SOAR v1alpha) ──
SIEMPLIFY_URL = os.getenv("SIEMPLIFY_URL", "https://linus2.siemplify-soar.com")
SIEMPLIFY_API_KEY = os.getenv("SIEMPLIFY_API_KEY", "")
SIEMPLIFY_BASE = f"{SIEMPLIFY_URL}/api/external/v1"

# Siemplify priority map (numeric) → string labels
_SIEMPLIFY_PRIORITY = {"INFO": -1, "LOW": 40, "MEDIUM": 60, "HIGH": 80, "CRITICAL": 100}
_SIEMPLIFY_PRIORITY_INV = {-1: "INFO", 0: "INFORMATIONAL", 40: "LOW", 60: "MEDIUM", 80: "HIGH", 100: "CRITICAL"}

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='{"severity":"%(levelname)s","message":"%(message)s","tool":"%(name)s"}',
)
logger = logging.getLogger("google-native-mcp")

# ═══════════════════════════════════════════════════════════════
# MCP SERVER
# ═══════════════════════════════════════════════════════════════

app_mcp = FastMCP("google-native-mcp", json_response=True)

# Session management endpoints
@app_mcp.tool()
def create_session() -> str:
    """Create a new session for maintaining context across multiple queries."""
    session_id = session_store.create_session()
    return json.dumps({"session_id": session_id, "status": "created"})

@app_mcp.tool()
def get_session(session_id: str) -> str:
    """Get current session state and investigation notes."""
    session = session_store.get_session(session_id)
    if not session:
        return json.dumps({"error": "Session not found"})
    return json.dumps(session, default=str)

@app_mcp.tool()
def set_session_context(session_id: str, case_id: str = "", alert_id: str = "", ip: str = "", user: str = "", domain: str = "") -> str:
    """Update session context with investigation targets."""
    session = session_store.get_session(session_id)
    if not session:
        return json.dumps({"error": "Session not found"})
    
    if case_id:
        session_store.update_session(session_id, 'last_case_id', case_id)
    if alert_id:
        session_store.update_session(session_id, 'last_alert_id', alert_id)
    if ip:
        session_store.update_session(session_id, 'last_ip', ip)
    if user:
        session_store.update_session(session_id, 'last_user', user)
    if domain:
        session_store.update_session(session_id, 'last_domain', domain)
    
    return json.dumps({"status": "updated", "session_id": session_id})

@app_mcp.tool()
def add_investigation_note(session_id: str, note: str) -> str:
    """Add an investigation note to the session."""
    session = session_store.get_session(session_id)
    if not session:
        return json.dumps({"error": "Session not found"})
    
    session_store.add_note(session_id, note)
    return json.dumps({"status": "note_added", "total_notes": len(session['investigation_notes'])})

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════


def validate_project_id(pid: str) -> str:
    if not pid or not re.match(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$", pid):
        raise ValueError(f"Invalid project ID: '{pid}'")
    return pid


def sanitize_rule_input(value: str) -> str:
    """Strip characters that could break or inject into YARA-L rule structure."""
    return re.sub(r'["\{\}\n\r\\]', '', value)[:200]


def validate_indicator(ind: str) -> str:
    if not ind or len(ind) > 256:
        raise ValueError("Indicator must be non-empty and under 256 chars.")
    if not re.match(r"^[a-zA-Z0-9\.\-\:\/\_\@]+$", ind):
        raise ValueError(f"Invalid indicator format: '{ind}'")
    return ind


def get_adc_token() -> str:
    try:
        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        creds.refresh(GCPRequest())
        return creds.token
    except DefaultCredentialsError:
        raise RuntimeError("No ADC found. Configure Workload Identity or run gcloud auth application-default login.")
    except RefreshError as e:
        raise RuntimeError(f"ADC token refresh failed: {e}")


def _get_o365_token() -> str:
    """Get Microsoft Graph API access token via client credentials flow."""
    if not all([O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET]):
        raise RuntimeError("O365 credentials not configured. Set O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET.")
    resp = requests.post(
        f"https://login.microsoftonline.com/{O365_TENANT_ID}/oauth2/v2.0/token",
        data={
            "client_id": O365_CLIENT_ID,
            "client_secret": O365_CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"O365 token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]


def _get_crowdstrike_token() -> str:
    """Get CrowdStrike Falcon API OAuth2 token."""
    if not all([CS_CLIENT_ID, CS_CLIENT_SECRET]):
        raise RuntimeError("CrowdStrike credentials not configured. Set CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET.")
    resp = requests.post(
        f"{CS_BASE_URL}/oauth2/token",
        data={"client_id": CS_CLIENT_ID, "client_secret": CS_CLIENT_SECRET},
        timeout=15,
    )
    if resp.status_code != 201:
        raise RuntimeError(f"CrowdStrike token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]


def _secops_headers() -> dict:
    return {
        "Authorization": f"Bearer {get_adc_token()}",
        "Content-Type": "application/json",
    }


def _siemplify_headers() -> dict:
    return {"AppKey": SIEMPLIFY_API_KEY, "Content-Type": "application/json"}


def _expand_threat_actor_query(query: str) -> list:
    """Use Gemini to expand a category/list query into specific threat actor names."""
    CATEGORY_KEYWORDS = ["latest", "recent", "top", "list", "group", "unc", "apt ", "all ", "best", "known", "chinese", "russian", "iranian", "north korean", "ransomware", "nation"]
    q_lower = query.lower()
    if not any(k in q_lower for k in CATEGORY_KEYWORDS):
        return [query]  # Single named actor — no expansion needed
    try:
        token = get_adc_token()
        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/{GEMINI_MODEL}:generateContent"
        )
        prompt = (
            f"The user wants to search for threat actors matching: \"{query}\"\n\n"
            "Return a JSON array of up to 8 specific threat actor names to search for.\n"
            "Use well-known designations: APT28, UNC3944, Lazarus Group, Scattered Spider, etc.\n"
            "Respond with ONLY a JSON array like: [\"APT28\", \"APT29\", \"Cozy Bear\"]\n"
            "No explanation, no markdown, just the JSON array."
        )
        resp = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"contents": [{"role": "user", "parts": [{"text": prompt}]}]},
            timeout=30,
        )
        if resp.status_code == 200:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            text = text.strip("```json").strip("```").strip()
            names = json.loads(text)
            if isinstance(names, list) and names:
                return names
    except Exception:
        pass
    return [query]


def translate_nl_to_udm_query(natural_language: str) -> str:
    """Translate natural language to UDM query using Gemini."""
    try:
        token = get_adc_token()
        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/{GEMINI_MODEL}:generateContent"
        )
        prompt = (
            "You are a Google SecOps Chronicle UDM query expert.\n\n"
            "STRICT RULES:\n"
            "1. Use ONLY lowercase 'and', 'or', 'not' operators — NEVER uppercase AND/OR/NOT\n"
            "2. Do NOT include any time filters (_time, timestamp, hours, etc.) — time is handled separately\n"
            "3. String values must use double quotes\n"
            "4. Return ONLY the raw UDM query string — no explanation, no backticks, no markdown\n\n"
            "Field reference:\n"
            "  metadata.event_type = \"USER_LOGIN\"  (login events)\n"
            "  metadata.event_type = \"NETWORK_CONNECTION\"  (network)\n"
            "  metadata.event_type = \"PROCESS_EXECUTION\"  (processes)\n"
            "  metadata.event_type = \"FILE_CREATION\"  (file activity)\n"
            "  security_result.action = \"BLOCK\"  (blocked/failed actions)\n"
            "  security_result.action = \"ALLOW\"  (successful actions)\n"
            "  security_result.severity = \"HIGH\"  (HIGH, MEDIUM, LOW, INFO)\n"
            "  principal.ip  (source IP)\n"
            "  principal.user.userid  (source user)\n"
            "  principal.hostname  (source host)\n"
            "  target.ip  (destination IP)\n"
            "  target.hostname  (destination host)\n"
            "  target.user.userid  (target user)\n"
            "  network.dns.questions.name  (DNS queries)\n"
            "  about.file.sha256  (file hashes)\n\n"
            "EXAMPLES:\n"
            "  'failed logins' → metadata.event_type = \"USER_LOGIN\" and security_result.action = \"BLOCK\"\n"
            "  'successful logins' → metadata.event_type = \"USER_LOGIN\" and security_result.action = \"ALLOW\"\n"
            "  'DNS queries for evil.com' → network.dns.questions.name = \"evil.com\"\n"
            "  'connections from 1.2.3.4' → metadata.event_type = \"NETWORK_CONNECTION\" and principal.ip = \"1.2.3.4\"\n\n"
            f"Natural language: {natural_language}\n\nUDM Query:"
        )
        resp = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"contents": [{"role": "user", "parts": [{"text": prompt}]}]},
            timeout=120,
        )
        if resp.status_code == 200:
            query = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            query = query.strip("`").strip()
            return query
        return ""
    except Exception as e:
        logger.error(f"UDM query translation failed: {e}")
        return ""


def parse_time_range(hours_back: int = 24, start_time: str = "", end_time: str = "") -> tuple:
    """
    Parse time range parameters into ISO 8601 timestamps.
    Returns (start_iso, end_iso).
    Priority: explicit start_time/end_time > hours_back
    """
    try:
        end = datetime.now(timezone.utc)
        if end_time:
            try:
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            except:
                pass
        if start_time:
            try:
                start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                return (start.isoformat(), end.isoformat())
            except:
                pass
        hours_back = min(max(1, hours_back), 8760)
        start = end - timedelta(hours=hours_back)
        return (start.isoformat(), end.isoformat())
    except Exception as e:
        logger.warning(f"Time range parse error: {e}, using default")
        return ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(), datetime.now(timezone.utc).isoformat())


# ═══════════════════════════════════════════════════════════════
# 🔍 DISCOVERY & HUNTING
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_scc_findings(project_id: str = "", severity: str = "CRITICAL", max_results: int = 10, state: str = "ACTIVE", hours_back: int = 720, start_time: str = "", end_time: str = "", start_time_hours_ago: int = 0, time_range: str = "") -> str:
    """Fetch vulnerabilities from Security Command Center. Filters by severity and state (ACTIVE, INACTIVE, RESOLVED) with optional time range filtering."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        max_results = min(max(1, max_results), 50)
        
        # handle start_time_hours_ago alias
        if start_time_hours_ago > 0:
            hours_back = start_time_hours_ago
        # Build dynamic filter with time range support
        filter_str = f'state="{state.upper()}" AND severity="{severity.upper()}"'
        if hours_back > 0:
            hours_back = min(max(1, hours_back), 8760)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
            cutoff_iso = cutoff.isoformat()
            filter_str += f' AND eventTime >= "{cutoff_iso}"'
        
        client = securitycenter.SecurityCenterClient()
        findings = client.list_findings(request={
            "parent": f"projects/{project_id}/sources/-",
            "filter": filter_str,
        })
        results = []
        for i, f in enumerate(findings):
            if i >= max_results:
                break
            # Extract rich finding data
            finding_obj = f.finding
            finding_dict = {
                "resource_name": finding_obj.resource_name,
                "category": finding_obj.category,
                "severity": str(finding_obj.severity),
                "create_time": str(finding_obj.create_time),
                "external_uri": finding_obj.external_uri or "",
                "description": (finding_obj.description or "")[:500],
                "state": str(finding_obj.state),
                "vulnerability": {
                    "cve_id": getattr(getattr(finding_obj.vulnerability, 'cve', None), 'id', None),
                    "cvss_score": getattr(getattr(finding_obj.vulnerability, 'cvss_v3', None), 'base_score', None),
                } if finding_obj.vulnerability else None,
                "mute_state": str(finding_obj.mute) if hasattr(finding_obj, 'mute') else "UNMUTED",
                "finding_class": finding_obj.finding_class if hasattr(finding_obj, 'finding_class') else "UNKNOWN",
            }
            results.append(finding_dict)
        logger.info(f"SCC: {len(results)} {severity} findings (state={state}, hours_back={hours_back}) for {project_id}")
        return json.dumps({"scc_findings": results, "count": len(results), "query": {"severity": severity, "state": state, "hours_back": hours_back}})
    except (PermissionDenied, NotFound, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def query_cloud_logging(project_id: str = "", filter_string: str = "", query: str = "", max_results: int = 10, hours_back: int = 24, start_time: str = "", end_time: str = "", severity: str = "", log_name: str = "", time_range: str = "") -> str:
    """[GCP NATIVE - NOT SECOPS] Query Cloud Logging for IAM, compute, audit trails. Use: severity=ERROR, logName:cloudaudit, resource.type=gce_instance."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        # Accept both 'filter_string' and 'query' parameters
        # Also accept standalone severity/log_name params and build filter
        parts = []
        if severity:
            parts.append(f'severity={severity.upper()}')
        if log_name:
            parts.append(f'logName:"{log_name}"')
        base = query or filter_string
        if base:
            parts.insert(0, base)
        final_filter = ' AND '.join(parts) if parts else ""
        if not final_filter or len(final_filter.strip()) < 3:
            # Default to recent entries if no filter given
            final_filter = 'severity >= "DEFAULT"'
        
        # Parse time range
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time)
        
        # Add time range to filter
        time_filter = f'timestamp >= "{start_iso}" AND timestamp <= "{end_iso}"'
        combined_filter = f"({final_filter}) AND {time_filter}"
        
        client = cloud_logging.Client(project=project_id)
        entries = client.list_entries(filter_=combined_filter, max_results=min(max_results, 50))
        logs = [{"timestamp": str(e.timestamp), "severity": e.severity, "payload": str(e.payload)[:2000]} for e in entries]
        logger.info(f"Cloud Logging: {len(logs)} entries for {project_id}")
        return json.dumps({"cloud_logs": logs, "count": len(logs), "time_range": {"start": start_iso, "end": end_iso}})
    except (PermissionDenied, ResourceExhausted, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def search_secops_udm(query: str = "", udm_query: str = "", hours_back: int = 24, max_events: int = 100, start_time: str = "", end_time: str = "", time_range: str = "", limit: int = 0, count: int = 0) -> str:
    """[SECOPS CHRONICLE] Direct UDM queries. Advanced threat hunting with Chronicle metadata: event_type, severity, action, source IP, target user, etc."""
    try:
        final_query = query or udm_query
        if not final_query or len(final_query.strip()) < 5:
            return json.dumps({"error": "Query too short"})

        # If the query looks like natural language rather than UDM syntax, convert it
        import re as _re
        _looks_like_nl = not any(x in final_query for x in ['metadata.', 'security_result.', 'principal.', 'target.', 'network.', 'about.'])
        if _looks_like_nl:
            converted = _nl_to_udm(final_query)
            if converted:
                final_query = converted

        # Sanitize common Gemini mistakes before sending to Chronicle
        final_query = _re.sub(r'\bAND\b', 'and', final_query)
        final_query = _re.sub(r'\bOR\b', 'or', final_query)
        final_query = _re.sub(r'\bNOT\b', 'not', final_query)
        final_query = _re.sub(r'\s+and\s+_time\s*[><=!]+\s*["\'\w]+', '', final_query)
        final_query = _re.sub(r'\s+and\s+metadata\.event_timestamp\s*[><=!]+\s*["\'\w]+', '', final_query)
        final_query = final_query.strip().rstrip('and').rstrip('or').strip()

        # Accept limit/count as aliases for max_events
        if limit > 0:
            max_events = limit
        elif count > 0:
            max_events = count
        max_events = min(max(1, max_events), 10000)
        
        # Parse time range
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time)
        start_dt = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_iso.replace('Z', '+00:00'))
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.search_udm(
            query=final_query,
            start_time=start_dt,
            end_time=end_dt,
            max_events=max_events
        )
        events = result.get("events", []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        return json.dumps({
            "events": events[:max_events],
            "total_events": len(events),
            "query": final_query,
            "time_range": {"start": start_iso, "end": end_iso},
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_secops_detections(hours_back: int = 24, max_results: int = 50, start_time: str = "", end_time: str = "") -> str:
    """List recent YARA-L detection alerts with rule names, severity, and outcomes with time range filtering."""
    try:
        max_results = min(max(1, max_results), 1000)
        # Parse time range
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time)
        start_dt = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_iso.replace('Z', '+00:00'))
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_detections(
            page_size=max_results,
            start_time=start_dt,
            end_time=end_dt
        )
        detections = result.get('detections', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        return json.dumps({"detections": detections[:max_results], "count": len(detections), "time_range": {"start": start_iso, "end": end_iso}})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def check_ingestion_health(log_type: str = "", hours_back: int = 1) -> str:
    """
    Check for unparsed logs in SecOps. If log_type is provided, checks that specific source.
    Returns unparsed volume to identify silent parser failures.
    """
    try:
        hours_back = min(max(1, hours_back), 168)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        end_dt = now
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # Use search_udm to check event volume — proxy for ingestion health
        udm_query = f'metadata.log_type = "{log_type.upper()}"' if log_type else 'metadata.event_type = "USER_LOGIN" OR metadata.event_type = "NETWORK_CONNECTION" OR metadata.event_type = "PROCESS_LAUNCH"'
        try:
            result = chronicle.search_udm(
                query=udm_query,
                start_time=start_dt,
                end_time=end_dt,
                max_events=500,
            )
            events = result.get('events', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
            # Count by log type
            log_types = {}
            for e in events:
                lt = e.get('metadata', {}).get('log_type', 'UNKNOWN') if isinstance(e, dict) else 'UNKNOWN'
                log_types[lt] = log_types.get(lt, 0) + 1
            return json.dumps({
                "status": "ok",
                "total_events": len(events),
                "log_type": log_type or "all",
                "hours_back": hours_back,
                "events_by_log_type": log_types,
                "note": "Event count is a proxy for ingestion health. Zero events may indicate ingestion issues."
            })
        except Exception as e2:
            return json.dumps({"status": "unavailable", "error": str(e2), "hours_back": hours_back})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🧠 INTELLIGENCE & ENRICHMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def enrich_indicator(indicator: str = "", value: str = "", indicator_type: str = "auto", type: str = "") -> str:
    """Enrich an IP, domain, URL, or file hash using Google Threat Intel / VirusTotal."""
    try:
        # Accept both 'indicator' and 'value' parameters
        final_indicator = indicator or value
        if not final_indicator:
            return json.dumps({"error": "indicator or value parameter required"})
        final_indicator = validate_indicator(final_indicator)
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})

        if indicator_type == "auto":
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", final_indicator):
                indicator_type = "ip"
            elif re.match(r"^[a-fA-F0-9]{32}$", final_indicator) or re.match(r"^[a-fA-F0-9]{64}$", final_indicator):
                indicator_type = "hash"
            elif "/" in final_indicator or "http" in final_indicator.lower():
                indicator_type = "url"
            else:
                indicator_type = "domain"

        vt = "https://www.virustotal.com/api/v3"
        urls = {"ip": f"{vt}/ip_addresses/{final_indicator}", "domain": f"{vt}/domains/{final_indicator}",
                "hash": f"{vt}/files/{final_indicator}", "url": f"{vt}/search?query={final_indicator}"}
        resp = requests.get(urls.get(indicator_type, urls["url"]),
                            headers={"x-apikey": GTI_API_KEY}, timeout=120)

        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {}) if isinstance(resp.json().get("data"), dict) else {}
            result = {"indicator": indicator, "type": indicator_type,
                      "reputation": attrs.get("reputation", "N/A"),
                      "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                      "tags": attrs.get("tags", [])}
            if indicator_type == "ip":
                result.update({"asn": attrs.get("asn"), "as_owner": attrs.get("as_owner"), "country": attrs.get("country")})
            elif indicator_type == "hash":
                result.update({"file_type": attrs.get("type_description"), "file_name": attrs.get("meaningful_name"),
                               "size": attrs.get("size"), "first_seen": attrs.get("first_submission_date")})
            return json.dumps(result)
        elif resp.status_code == 404:
            return json.dumps({"indicator": indicator, "result": "NOT_FOUND", "note": "May be novel/zero-day."})
        return json.dumps({"error": f"GTI [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def extract_iocs_from_detections(hours_back: int = 24) -> str:
    """
    Bulk extract all IOCs (IPs, domains, hashes, emails) from recent detections.
    Returns deduplicated sets for blocklist or Data Table population.
    """
    try:
        hours_back = min(max(1, hours_back), 168)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        end_dt = now
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        
        ips, domains, hashes, emails = set(), set(), set(), set()
        page_count = 0
        
        result = chronicle.list_detections(
            page_size=1000,
            start_time=start_dt,
            end_time=end_dt
        )
        detections = result.get('detections', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        page_count = 1
        
        for det in detections:
            det_dict = det if isinstance(det, dict) else {}
            for elem in det_dict.get("collectionElements", []):
                for ref in elem.get("references", []):
                    event = ref.get("event", {})
                    for field in ("target", "principal", "src"):
                        entity = event.get(field, {})
                        for ip in entity.get("ip", []):
                            ips.add(ip)
                        hostname = entity.get("hostname", "")
                        if hostname and "." in hostname:
                            domains.add(hostname.lower())
                        file_info = entity.get("file", {})
                        if file_info.get("sha256"):
                            hashes.add(file_info["sha256"].lower())
                        if file_info.get("md5"):
                            hashes.add(file_info["md5"].lower())
                        user = entity.get("user", {})
                        for email in user.get("email_addresses", []):
                            emails.add(email.lower())
        
        ioc_result = {
            "ips": sorted(ips), "domains": sorted(domains),
            "hashes": sorted(hashes), "emails": sorted(emails),
            "totals": {"ips": len(ips), "domains": len(domains), "hashes": len(hashes), "emails": len(emails)},
            "detections_processed": len(detections),
        }
        logger.info(f"IOC extraction: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes, {len(emails)} emails")
        return json.dumps(ioc_result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def vertex_ai_investigate(context: str, task: str = "Analyze and provide a threat assessment.", model: str = "gemini-2.0-flash") -> str:
    """Use Vertex AI (Gemini) to analyze security findings and generate investigation reports."""
    try:
        from google.cloud import aiplatform
        from vertexai.generative_models import GenerativeModel
        aiplatform.init(project=SECOPS_PROJECT_ID, location=SECOPS_REGION)
        prompt = f"""You are an expert security analyst in a Google SecOps environment.

TASK: {task}

SECURITY CONTEXT:
{context[:10000]}

Provide: 1) THREAT ASSESSMENT (severity + confidence) 2) KEY FINDINGS 3) ATTACK NARRATIVE 4) RECOMMENDED ACTIONS 5) DETECTION GAPS
Reference UDM fields, MITRE ATT&CK techniques, and Google SecOps capabilities."""

        response = GenerativeModel(model).generate_content(prompt)
        return json.dumps({"analysis": response.text, "model": model})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📋 DATA TABLE MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_data_tables() -> str:
    """List all Data Tables in the SecOps instance."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_data_tables()
        return json.dumps(result) if not isinstance(result, str) else result
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_data_table(table_name: str) -> str:
    """Read the contents of a specific Data Table."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        table_info = chronicle.get_data_table(table_name=table_name)
        rows = chronicle.list_data_table_rows(table_name=table_name)
        result = table_info if isinstance(table_info, dict) else (json.loads(table_info) if isinstance(table_info, str) else {})
        result['rows'] = rows.get('rows', []) if isinstance(rows, dict) else (rows if isinstance(rows, list) else [])
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_data_table(table_name: str, rows: list, description: str = "") -> str:
    """
    Update a Data Table with new rows. Overwrites existing content.
    Each row is a list of string values matching the table's column schema.
    Use for VIP lists, IOC blocklists, TI feeds, ASN exclusions, etc.
    """
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        formatted_rows = [{"values": row if isinstance(row, list) else [row]} for row in rows]
        try:
            result = chronicle.replace_data_table_rows(
                table_name=table_name,
                rows=formatted_rows
            )
        except Exception:
            result = chronicle.update_data_table(
                table_name=table_name,
                rows=formatted_rows,
                description=description or ""
            )
        logger.info(f"Data Table '{table_name}' updated: {len(rows)} rows")
        return json.dumps({"status": "success", "table": table_name, "rows_written": len(rows)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ DETECTION MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_rules(page_size: int = 100, limit: int = 0, max_results: int = 0, count: int = 0) -> str:
    """List all YARA-L rules in the SecOps instance with their enabled/disabled status."""
    try:
        # Accept any count/limit/max_results parameter
        final_page_size = limit or max_results or count or page_size
        final_page_size = min(max(1, final_page_size), 1000)
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_rules(page_size=final_page_size)
        return json.dumps(result) if not isinstance(result, str) else result
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def toggle_rule(rule_id: str, enabled: bool) -> str:
    """Enable or disable a YARA-L detection rule by its rule ID."""
    try:
        # Chronicle v1alpha uses PATCH on the deployment sub-resource
        deployment_url = f"{SECOPS_BASE_URL}/rules/{rule_id}/deployment"
        patch_resp = requests.patch(
            deployment_url,
            headers=_secops_headers(),
            json={"enabled": enabled},
            params={"update_mask": "enabled"},
            timeout=15,
        )
        if patch_resp.status_code in (200, 204):
            logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}")
            return json.dumps({"status": "success", "rule_id": rule_id, "enabled": enabled})

        # Fallback: try :enableLiveRule / :disableLiveRule verb
        action = "enableLiveRule" if enabled else "disableLiveRule"
        verb_resp = requests.post(
            f"{SECOPS_BASE_URL}/rules/{rule_id}:{action}",
            headers=_secops_headers(),
            json={},
            timeout=15,
        )
        if verb_resp.status_code in (200, 204):
            logger.info(f"Rule {rule_id} toggled via :{action}")
            return json.dumps({"status": "success", "rule_id": rule_id, "enabled": enabled, "method": action})

        return json.dumps({
            "error": f"Both toggle methods failed",
            "patch_status": patch_resp.status_code,
            "verb_status": verb_resp.status_code,
            "detail": verb_resp.text[:300],
            "note": "Enable manually in Chronicle console → Detection Engine → Rules",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📧 EMAIL CONTAINMENT (Microsoft Graph)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete", confirm: bool = False) -> str:
    """
    Purge an email from an Office 365 mailbox using Microsoft Graph API.
    Uses the internet Message-ID header to locate the email, then executes a Hard or Soft Delete.

    Args:
        target_mailbox: The user's email address (e.g., user@company.com)
        message_id: The RFC 2822 Message-ID header value
        purge_type: "hardDelete" (bypasses trash) or "softDelete" (moves to trash)
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "purge_email_o365", "target": target_mailbox,
            "warning": f"This will {purge_type} email '{message_id}' from mailbox '{target_mailbox}'. Re-invoke with confirm=True to proceed."})
    try:
        token = _get_o365_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Step 1: Find the email by internet Message-ID
        search_url = f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages"
        params = {"$filter": f"internetMessageId eq '{message_id}'", "$select": "id,subject,from"}
        search_resp = requests.get(search_url, headers=headers, params=params, timeout=15)

        if search_resp.status_code != 200:
            return json.dumps({"error": f"Graph search failed [{search_resp.status_code}]", "detail": search_resp.text[:300]})

        messages = search_resp.json().get("value", [])
        if not messages:
            return json.dumps({"status": "not_found", "detail": f"No email with Message-ID '{message_id}' in {target_mailbox}"})

        internal_id = messages[0]["id"]
        subject = messages[0].get("subject", "unknown")

        # Step 2: Execute the purge
        if purge_type == "hardDelete":
            del_resp = requests.delete(f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}",
                                        headers=headers, timeout=15)
        else:
            del_resp = requests.post(f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}/move",
                                      headers=headers, json={"destinationId": "deleteditems"}, timeout=15)

        if del_resp.status_code in (200, 201, 204):
            logger.info(f"O365 purge: {purge_type} '{subject}' from {target_mailbox}")
            return json.dumps({"status": "purged", "mailbox": target_mailbox, "subject": subject, "purge_type": purge_type})
        return json.dumps({"error": f"Purge failed [{del_resp.status_code}]", "detail": del_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)}, default=str)
    except Exception as e:
        return json.dumps({"error": f"O365 purge error: {e}"}, default=str)


# ═══════════════════════════════════════════════════════════════
# 🔑 IDENTITY CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def suspend_okta_user(user_email: str, clear_sessions: bool = True, confirm: bool = False) -> str:
    """
    Suspend a user in Okta and optionally clear all active sessions.
    Used for compromised account containment -- blocks new logins and kills existing tokens.

    Args:
        user_email: The user's email address
        clear_sessions: Whether to also clear active sessions
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "suspend_okta_user", "target": user_email,
            "warning": f"This will suspend Okta user '{user_email}' and clear_sessions={clear_sessions}. Re-invoke with confirm=True to proceed."})
    try:
        if not all([OKTA_DOMAIN, OKTA_API_TOKEN]):
            return json.dumps({"error": "Okta credentials not configured"})
        headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Content-Type": "application/json"}

        # Find user by email
        user_resp = requests.get(f"https://{OKTA_DOMAIN}/api/v1/users/{user_email}",
                                  headers=headers, timeout=15)
        if user_resp.status_code != 200:
            return json.dumps({"error": f"User not found [{user_resp.status_code}]"})

        user_id = user_resp.json()["id"]
        results = []

        # Suspend the user
        susp_resp = requests.post(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/lifecycle/suspend",
                                   headers=headers, timeout=15)
        results.append(f"Suspend: {susp_resp.status_code}")

        # Clear sessions
        if clear_sessions:
            sess_resp = requests.delete(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/sessions",
                                         headers=headers, timeout=15)
            results.append(f"Clear sessions: {sess_resp.status_code}")

        logger.info(f"Okta containment: {user_email} suspended, sessions cleared={clear_sessions}")
        return json.dumps({"status": "contained", "user": user_email, "actions": results})
    except Exception as e:
        return json.dumps({"error": f"Okta error: {e}"})


@app_mcp.tool()
def revoke_azure_ad_sessions(user_email: str, confirm: bool = False) -> str:
    """Revoke all active sign-in sessions for an Azure AD / Entra ID user.

    Args:
        user_email: The user's email address
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "revoke_azure_ad_sessions", "target": user_email,
            "warning": f"This will revoke all Azure AD sign-in sessions for '{user_email}'. Re-invoke with confirm=True to proceed."})
    try:
        if not all([AZURE_AD_TENANT_ID, AZURE_AD_CLIENT_ID, AZURE_AD_CLIENT_SECRET]):
            return json.dumps({"error": "Azure AD credentials not configured"})

        # Get token
        token_resp = requests.post(
            f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}/oauth2/v2.0/token",
            data={"client_id": AZURE_AD_CLIENT_ID, "client_secret": AZURE_AD_CLIENT_SECRET,
                  "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
            timeout=15,
        )
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Revoke sessions
        resp = requests.post(f"https://graph.microsoft.com/v1.0/users/{user_email}/revokeSignInSessions",
                              headers=headers, timeout=15)

        if resp.status_code == 200:
            logger.info(f"Azure AD sessions revoked for {user_email}")
            return json.dumps({"status": "revoked", "user": user_email})
        return json.dumps({"error": f"Revoke failed [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": f"Azure AD error: {e}"})


# ═══════════════════════════════════════════════════════════════
# ☁️ CLOUD CREDENTIAL CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def revoke_aws_access_keys(target_user: str, confirm: bool = False) -> str:
    """Disable all active AWS IAM access keys for a user. Stops leaked credential abuse.

    Args:
        target_user: The AWS IAM username
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "revoke_aws_access_keys", "target": target_user,
            "warning": f"This will disable ALL active IAM access keys for AWS user '{target_user}'. Re-invoke with confirm=True to proceed."})
    try:
        if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
            return json.dumps({"error": "AWS credentials not configured"})
        import boto3
        from botocore.exceptions import ClientError
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        disabled = []
        paginator = iam.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=target_user):
            for key in page["AccessKeyMetadata"]:
                if key["Status"] == "Active":
                    iam.update_access_key(UserName=target_user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
                    disabled.append(key["AccessKeyId"])
        logger.info(f"AWS keys disabled for {target_user}: {disabled}")
        return json.dumps({"status": "contained", "user": target_user, "keys_disabled": disabled})
    except Exception as e:
        return json.dumps({"error": f"AWS IAM error: {e}"})


@app_mcp.tool()
def revoke_aws_sts_sessions(target_user: str, confirm: bool = False) -> str:
    """
    Deny all pre-existing STS sessions for an AWS IAM user.
    Critical: disabling access keys does NOT invalidate already-assumed roles.
    This attaches an inline deny-all policy conditioned on token issue time.

    Args:
        target_user: The AWS IAM username
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "revoke_aws_sts_sessions", "target": target_user,
            "warning": f"This will attach a deny-all policy to AWS user '{target_user}', revoking all pre-existing STS sessions. Re-invoke with confirm=True to proceed."})
    try:
        if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
            return json.dumps({"error": "AWS credentials not configured"})
        import boto3
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
                           "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}}]
        })
        iam.put_user_policy(UserName=target_user, PolicyName="SOAR_Emergency_Session_Revocation", PolicyDocument=policy)
        logger.info(f"AWS STS sessions revoked for {target_user} (tokens before {now})")
        return json.dumps({"status": "sessions_revoked", "user": target_user, "cutoff": now})
    except Exception as e:
        return json.dumps({"error": f"AWS STS error: {e}"})


@app_mcp.tool()
def revoke_gcp_sa_keys(project_id: str = "", service_account_email: str = "", confirm: bool = False) -> str:
    """Delete all user-managed keys for a GCP service account. Stops leaked SA key abuse.

    Args:
        project_id: GCP project ID
        service_account_email: The service account email
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "revoke_gcp_sa_keys", "target": service_account_email,
            "warning": f"This will delete ALL user-managed keys for GCP service account '{service_account_email}'. Re-invoke with confirm=True to proceed."})
    try:
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resource = f"projects/{project_id}/serviceAccounts/{service_account_email}"
        keys_resp = requests.get(
            f"https://iam.googleapis.com/v1/{resource}/keys?keyTypes=USER_MANAGED",
            headers=headers, timeout=15,
        )
        if keys_resp.status_code != 200:
            return json.dumps({"error": f"List keys failed [{keys_resp.status_code}]"})
        deleted = []
        for key in keys_resp.json().get("keys", []):
            key_name = key["name"]
            del_resp = requests.delete(f"https://iam.googleapis.com/v1/{key_name}", headers=headers, timeout=15)
            if del_resp.status_code in (200, 204):
                deleted.append(key_name.split("/")[-1])
        logger.info(f"GCP SA keys deleted for {service_account_email}: {deleted}")
        return json.dumps({"status": "contained", "sa": service_account_email, "keys_deleted": deleted})
    except Exception as e:
        return json.dumps({"error": f"GCP IAM error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 🖥️ ENDPOINT CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def isolate_crowdstrike_host(hostname: str = "", device_id: str = "", confirm: bool = False) -> str:
    """
    Network-isolate a host via CrowdStrike Falcon API.
    The host can still communicate with the CrowdStrike cloud for remote forensics
    but is completely disconnected from the internal network.

    Provide either hostname or device_id. If hostname, we look up the device_id first.

    Args:
        hostname: The hostname to isolate
        device_id: The CrowdStrike device ID
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        target = hostname or device_id or "unknown"
        return json.dumps({"status": "confirmation_required", "action": "isolate_crowdstrike_host", "target": target,
            "warning": f"This will network-isolate host '{target}' via CrowdStrike. Re-invoke with confirm=True to proceed."})
    try:
        token = _get_crowdstrike_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Look up device_id by hostname if needed
        if not device_id and hostname:
            search_resp = requests.get(
                f"{CS_BASE_URL}/devices/queries/devices/v1",
                headers=headers,
                params={"filter": f'hostname:"{hostname}"'},
                timeout=15,
            )
            if search_resp.status_code == 200:
                ids = search_resp.json().get("resources", [])
                if not ids:
                    return json.dumps({"error": f"No CrowdStrike device found for hostname '{hostname}'"})
                device_id = ids[0]
            else:
                return json.dumps({"error": f"Device search failed [{search_resp.status_code}]"})

        if not device_id:
            return json.dumps({"error": "Provide hostname or device_id"})

        # Execute containment
        contain_resp = requests.post(
            f"{CS_BASE_URL}/devices/entities/devices-actions/v2?action_name=contain",
            headers=headers,
            json={"ids": [device_id]},
            timeout=15,
        )

        if contain_resp.status_code == 202:
            logger.info(f"CrowdStrike: host {device_id} ({hostname}) isolated")
            return json.dumps({"status": "isolated", "device_id": device_id, "hostname": hostname})
        return json.dumps({"error": f"Containment failed [{contain_resp.status_code}]", "detail": contain_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"CrowdStrike error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 📂 SOAR CASE MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def create_soar_case(
    title: str,
    description: str,
    priority: str = "MEDIUM",
    alert_source: str = "MCP_SERVER",
) -> str:
    """Create a new case in Siemplify SOAR."""
    try:
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/CreateManualCase",
            headers=_siemplify_headers(),
            json={
                "title": title,
                "reason": description,
                "priority": _SIEMPLIFY_PRIORITY.get(priority.upper(), 60),
                "environment": "Default Environment",
            },
            timeout=15,
            verify=False,
        )
        if resp.status_code in (200, 201):
            data = resp.json() if resp.text else {}
            case_id = data.get("caseId") or data.get("id") or data
            logger.info(f"SOAR case created: {title}")
            return json.dumps({"status": "created", "case_id": case_id, "title": title})
        return json.dumps({"error": f"Case creation [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_soar_case(
    case_id: str,
    comment: str = "",
    priority: str = "",
    status: str = "",
    close_reason: str = "",
) -> str:
    """
    Update an existing Siemplify SOAR case — add comments, change priority, or close.

    Args:
        case_id: The numeric Siemplify case ID
        comment: Text to add to the case wall
        priority: New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status: New status (OPEN, IN_PROGRESS, CLOSED)
        close_reason: Required when status=CLOSED
    """
    try:
        results = []

        if comment:
            resp = requests.post(
                f"{SIEMPLIFY_BASE}/cases/comments",
                headers=_siemplify_headers(),
                json={"caseId": int(case_id), "comment": comment},
                timeout=15,
                verify=False,
            )
            results.append(f"Comment: {resp.status_code}")

        if priority:
            resp = requests.post(
                f"{SIEMPLIFY_BASE}/cases/ChangeCasePriority",
                headers=_siemplify_headers(),
                json={"caseId": int(case_id), "priority": _SIEMPLIFY_PRIORITY.get(priority.upper(), 60)},
                timeout=15,
                verify=False,
            )
            results.append(f"Priority: {resp.status_code}")

        if status and status.upper() in ("CLOSED", "CLOSE"):
            resp = requests.post(
                f"{SIEMPLIFY_BASE}/cases/CloseCase",
                headers=_siemplify_headers(),
                json={"caseId": int(case_id), "rootCause": close_reason or "Resolved", "comment": close_reason or "Closed via MCP"},
                timeout=15,
                verify=False,
            )
            results.append(f"Close: {resp.status_code}")

        logger.info(f"SOAR case {case_id} updated: {results}")
        return json.dumps({"status": "updated", "case_id": case_id, "actions": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔎 NATURAL LANGUAGE SECURITY SEARCH (SecOps)
# ═══════════════════════════════════════════════════════════════


_UDM_QUICK_LOOKUP = {
    # login failures
    "failed login": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "failed logins": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "login failure": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "login failures": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "authentication failure": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "auth failure": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    "failed authentication": 'metadata.event_type = "USER_LOGIN" and security_result.action = "BLOCK"',
    # successful logins
    "successful login": 'metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW"',
    "successful logins": 'metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW"',
    "login success": 'metadata.event_type = "USER_LOGIN" and security_result.action = "ALLOW"',
    # all logins
    "login": 'metadata.event_type = "USER_LOGIN"',
    "logins": 'metadata.event_type = "USER_LOGIN"',
    "user login": 'metadata.event_type = "USER_LOGIN"',
    "user logins": 'metadata.event_type = "USER_LOGIN"',
    # network
    "network connections": 'metadata.event_type = "NETWORK_CONNECTION"',
    "dns queries": 'metadata.event_type = "NETWORK_DNS"',
    "http traffic": 'metadata.event_type = "NETWORK_HTTP"',
    # process
    "process execution": 'metadata.event_type = "PROCESS_EXECUTION"',
    "processes": 'metadata.event_type = "PROCESS_EXECUTION"',
    # file
    "file creation": 'metadata.event_type = "FILE_CREATION"',
    "file modification": 'metadata.event_type = "FILE_MODIFICATION"',
    # severity
    "high severity": 'security_result.severity = "HIGH"',
    "critical events": 'security_result.severity = "CRITICAL"',
}


def _nl_to_udm(search_text: str) -> str:
    """Convert NL to UDM — instant lookup first, Gemini fallback."""
    sl = search_text.lower().strip()
    # Direct lookup
    for key, q in _UDM_QUICK_LOOKUP.items():
        if key in sl:
            return q
    # Gemini fallback (reuse the fixed translate_nl_to_udm_query)
    return translate_nl_to_udm_query(search_text)


@app_mcp.tool()
def search_security_events(text: str = "", query: str = "", hours_back: int = 24, time_range: str = "", timerange: str = "", max_events: int = 100) -> str:
    """[SECOPS CHRONICLE] Search UDM for logins, malware, threats. Translates natural language to UDM: metadata.event_type=USER_LOGIN, security_result.action=ALLOW, etc."""
    try:
        search_text = text or query
        if not search_text or len(search_text.strip()) < 3:
            return json.dumps({"error": "Search text too short"})
        final_time_range = time_range or timerange
        if final_time_range:
            if "day" in final_time_range.lower():
                try: hours_back = int(final_time_range.split()[0]) * 24
                except: pass
            elif "hour" in final_time_range.lower():
                try: hours_back = int(final_time_range.split()[0])
                except: pass
        hours_back = min(max(1, hours_back), 8760)
        max_events = min(max(1, max_events), 10000)

        udm_query = _nl_to_udm(search_text)
        if not udm_query:
            return json.dumps({"error": "Could not translate query to UDM"})

        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.search_udm(
            query=udm_query,
            start_time=start_dt,
            end_time=now,
            max_events=max_events
        )
        events = result.get("events", []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        return json.dumps({"natural_language_query": search_text, "udm_query": udm_query, "events": events[:max_events], "count": len(events)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🚨 SECURITY ALERTS & ENTITY LOOKUP (SecOps)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_security_alerts(hours_back: int = 24, max_alerts: int = 10, limit: int = 0, count: int = 0, max_results: int = 0) -> str:
    """Retrieve recent security alerts from Google SecOps with time filtering."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        # Accept any count/limit/max_results/max_alerts parameter
        alert_limit = count or max_results or limit or max_alerts
        alert_limit = min(max(1, alert_limit), 1000)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.get(
            f"{SECOPS_BASE_URL}/alerts",
            headers=_secops_headers(),
            params={"startTime": start, "endTime": end, "pageSize": alert_limit},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            alerts = data.get("alerts", [])
            formatted = []
            for a in alerts[:alert_limit]:
                formatted.append({
                    "id": a.get("name", a.get("alertId", "")),
                    "rule_name": a.get("ruleName", a.get("detection", {}).get("ruleName", "unknown")),
                    "severity": a.get("severity", "unknown"),
                    "create_time": a.get("createTime", ""),
                    "status": a.get("status", ""),
                    "description": (a.get("description", "") or "")[:500],
                })
            return json.dumps({"alerts": formatted, "count": len(formatted), "hours_back": hours_back})
        return json.dumps({"error": f"Alerts API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def lookup_entity(entity_value: str, hours_back: int = 24) -> str:
    """Look up an entity (IP, domain, user, hash) in Google SecOps. Returns risk score, associated alerts, and entity context."""
    try:
        if not entity_value or len(entity_value.strip()) < 1:
            return json.dumps({"error": "Entity value is required"})
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.get(
            f"{SECOPS_BASE_URL}/entities:lookup",
            headers=_secops_headers(),
            params={"entityValue": entity_value, "startTime": start, "endTime": end},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "entity": entity_value,
                "risk_score": data.get("riskScore", data.get("entity", {}).get("riskScore", "N/A")),
                "first_seen": data.get("firstSeen", ""),
                "last_seen": data.get("lastSeen", ""),
                "alerts": data.get("alerts", []),
                "alert_count": len(data.get("alerts", [])),
                "entity_metadata": data.get("entity", data.get("metadata", {})),
            }
            return json.dumps(result)
        return json.dumps({"error": f"Entity lookup [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🦠 GTI / VIRUSTOTAL DEEP REPORTS
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_file_report(hash: str = "", file_hash: str = "", sha256: str = "", md5: str = "", sha1: str = "") -> str:
    """Get a comprehensive file analysis report from VirusTotal/GTI by file hash (MD5, SHA-1, or SHA-256). Returns detection stats, file type, names, and behavioral summary."""
    try:
        final_hash = hash or file_hash or sha256 or md5 or sha1
        if not final_hash or not re.match(r"^[a-fA-F0-9]{32,64}$", final_hash):
            return json.dumps({"error": "Invalid hash format. Provide MD5, SHA-1, or SHA-256."})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{final_hash}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "hash": final_hash,
                "id": data.get("id", ""),
                "file_type": attrs.get("type_description", "unknown"),
                "type_tag": attrs.get("type_tag", ""),
                "size": attrs.get("size"),
                "meaningful_name": attrs.get("meaningful_name", ""),
                "names": attrs.get("names", [])[:10],
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "reputation": attrs.get("reputation"),
                "tags": attrs.get("tags", []),
                "first_submission_date": attrs.get("first_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "sha256": attrs.get("sha256", ""),
                "md5": attrs.get("md5", ""),
                "sha1": attrs.get("sha1", ""),
                "sandbox_verdicts": attrs.get("sandbox_verdicts", {}),
                "popular_threat_classification": attrs.get("popular_threat_classification", {}),
            })
        elif resp.status_code == 404:
            return json.dumps({"hash": hash, "result": "NOT_FOUND", "note": "File not in VirusTotal database."})
        return json.dumps({"error": f"GTI [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_domain_report(domain: str = "", domain_name: str = "", site: str = "") -> str:
    """Get a comprehensive domain analysis report from VirusTotal/GTI. Returns reputation, registrar, DNS records, and detection stats."""
    try:
        final_domain = domain or domain_name or site
        if not final_domain or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", final_domain):
            return json.dumps({"error": "Invalid domain format"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{final_domain}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "domain": final_domain,
                "reputation": attrs.get("reputation"),
                "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date"),
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "last_dns_records": attrs.get("last_dns_records", [])[:20],
                "categories": attrs.get("categories", {}),
                "popularity_ranks": attrs.get("popularity_ranks", {}),
                "whois": (attrs.get("whois", "") or "")[:1000],
                "tags": attrs.get("tags", []),
                "total_votes": attrs.get("total_votes", {}),
            })
        elif resp.status_code == 404:
            return json.dumps({"domain": domain, "result": "NOT_FOUND"})
        return json.dumps({"error": f"GTI [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_ip_report(ip_address: str = "", ip: str = "", address: str = "", host: str = "") -> str:
    """Get a comprehensive IP address analysis report from VirusTotal/GTI. Returns ASN, country, reputation, and detection stats."""
    try:
        final_ip = ip_address or ip or address or host
        if not final_ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", final_ip):
            return json.dumps({"error": "Invalid IPv4 address format"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{final_ip}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "ip_address": final_ip,
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner", ""),
                "country": attrs.get("country", ""),
                "continent": attrs.get("continent", ""),
                "network": attrs.get("network", ""),
                "reputation": attrs.get("reputation"),
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "tags": attrs.get("tags", []),
                "total_votes": attrs.get("total_votes", {}),
                "whois": (attrs.get("whois", "") or "")[:1000],
            })
        elif resp.status_code == 404:
            return json.dumps({"ip_address": ip_address, "result": "NOT_FOUND"})
        return json.dumps({"error": f"GTI [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def search_threat_actors(threat_actor_name: str = "", actor_name: str = "", query: str = "", actor_query: str = "", threat_actor: str = "", limit: int = 10) -> str:
    """Search GTI (Google Threat Intelligence / VirusTotal Enterprise) for a threat actor. Returns collections/reports about the actor AND malware samples attributed to them with SHA256 hashes."""
    try:
        import json, requests
        final_query = threat_actor_name or actor_name or query or actor_query or threat_actor
        if not final_query or len(final_query.strip()) < 2:
            return json.dumps({"error": "Provide a threat actor name (e.g. APT28, Fancy Bear, Lazarus Group)"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})

        # Expand category queries ("latest 5 UNC groups") into specific actor names
        expanded_names = _expand_threat_actor_query(final_query)
        if len(expanded_names) > 1:
            # Multi-actor lookup — fan out and collect summaries
            results = []
            for name in expanded_names[:limit]:
                try:
                    gti_filter = f"collection_type:threat-actor and {name} and origin:'Google Threat Intelligence'"
                    r = requests.get(
                        "https://www.virustotal.com/api/v3/collections",
                        headers={"x-apikey": GTI_API_KEY},
                        params={"filter": gti_filter, "limit": 1},
                        timeout=30,
                    )
                    if r.status_code == 200 and r.json().get("data"):
                        p = r.json()["data"][0]
                        a = p.get("attributes", {})
                        results.append({
                            "name": a.get("name", name),
                            "id": p.get("id", ""),
                            "description": (a.get("description", "") or "")[:400],
                            "files_count": a.get("files_count", 0),
                            "domains_count": a.get("domains_count", 0),
                            "targeted_regions": a.get("targeted_regions", [])[:5],
                            "motivations": [m.get("value", "") for m in a.get("motivations", [])][:3],
                        })
                    else:
                        results.append({"name": name, "note": "Not found in GTI"})
                except Exception as ex:
                    results.append({"name": name, "error": str(ex)})
            return json.dumps({"query": final_query, "expanded_to": expanded_names, "results": results, "count": len(results)})

        limit = min(max(1, limit), 50)
        result = {"query": final_query, "source": "GTI Enterprise Plus (Google Threat Intelligence)"}
        
        # Step 1: Get the canonical GTI threat actor profile
        # Uses Google's official filter: collection_type:threat-actor AND name AND origin:'Google Threat Intelligence'
        gti_filter = f"collection_type:threat-actor and {final_query} and origin:'Google Threat Intelligence'"
        coll_resp = requests.get(
            "https://www.virustotal.com/api/v3/collections",
            headers={"x-apikey": GTI_API_KEY},
            params={"filter": gti_filter, "limit": 3},
            timeout=120,
        )
        
        profiles = []
        if coll_resp.status_code == 200:
            profiles = coll_resp.json().get("data", [])
        
        if not profiles:
            # Fallback: try broader name search
            fallback_resp = requests.get(
                "https://www.virustotal.com/api/v3/collections",
                headers={"x-apikey": GTI_API_KEY},
                params={"filter": f"name:{final_query}", "limit": 5},
                timeout=120,
            )
            if fallback_resp.status_code == 200:
                profiles = fallback_resp.json().get("data", [])
        
        if not profiles:
            return json.dumps({"error": f"No GTI threat actor profile found for '{final_query}'. Try the standard APT naming (APT28, APT33, APT44) or known aliases."})
        
        # Use the first (canonical) profile
        primary = profiles[0]
        attrs = primary.get("attributes", {})
        coll_id = primary.get("id", "")
        
        result["profile"] = {
            "id": coll_id,
            "name": attrs.get("name", ""),
            "description": (attrs.get("description", "") or "")[:1000],
            "files_count": attrs.get("files_count", 0),
            "domains_count": attrs.get("domains_count", 0),
            "ips_count": attrs.get("ip_addresses_count", 0),
            "targeted_regions": attrs.get("targeted_regions", []),
            "motivations": [m.get("value", "") for m in attrs.get("motivations", [])],
            "capabilities": [c.get("value", "") for c in attrs.get("capabilities", [])],
            "source_regions": attrs.get("source_regions", []),
        }
        
        # Step 2: Pull IOCs (domains, IPs, files) from the canonical profile
        for rel_type in ["domains", "ip_addresses", "files"]:
            rel_resp = requests.get(
                f"https://www.virustotal.com/api/v3/collections/{coll_id}/{rel_type}",
                headers={"x-apikey": GTI_API_KEY},
                params={"limit": 10},
                timeout=120,
            )
            if rel_resp.status_code == 200:
                items = rel_resp.json().get("data", [])
                if rel_type == "domains":
                    result["ioc_domains"] = [item.get("id", "") for item in items[:10]]
                elif rel_type == "ip_addresses":
                    result["ioc_ips"] = [item.get("id", "") for item in items[:10]]
                elif rel_type == "files":
                    result["ioc_files"] = [{
                        "sha256": item.get("attributes", {}).get("sha256", item.get("id", "")),
                        "name": item.get("attributes", {}).get("meaningful_name", item.get("attributes", {}).get("name", "")),
                        "malicious": item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    } for item in items[:10]]
        
        return json.dumps({"threat_actor": result})
    except Exception as e:
        return json.dumps({"error": str(e)})

@app_mcp.tool()
def search_malware_families(query: str = "", family_query: str = "", malware_query: str = "", limit: int = 10) -> str:
    """Search for malware family profiles in VirusTotal/GTI intelligence. Returns matching family names, descriptions, and classification."""
    try:
        final_query = query or family_query or malware_query
        if not final_query or len(final_query.strip()) < 2:
            return json.dumps({"error": "Query too short"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        limit = min(max(1, limit), 50)
        search_query = f'collection_type:"malware-family" AND {final_query}'
        resp = requests.get(
            "https://www.virustotal.com/api/v3/intelligence/search",
            headers={"x-apikey": GTI_API_KEY},
            params={"query": search_query, "limit": limit},
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            families = []
            for item in data.get("data", [])[:limit]:
                attrs = item.get("attributes", {})
                families.append({
                    "id": item.get("id", ""),
                    "name": attrs.get("name", attrs.get("meaningful_name", "")),
                    "description": (attrs.get("description", "") or "")[:500],
                    "aliases": attrs.get("aliases", []),
                    "classification": attrs.get("popular_threat_classification", {}),
                    "tags": attrs.get("tags", []),
                })
            return json.dumps({"query": query, "malware_families": families, "count": len(families)})
        return json.dumps({"error": f"GTI search [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ SCC VULNERABILITY & REMEDIATION
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def top_vulnerability_findings(project_id: str = "", max_findings: int = 20, count: int = 0, page_size: int = 0, limit: int = 0) -> str:
    """Get top vulnerability findings from Security Command Center sorted by Attack Exposure Score. Returns findings with severity, category, resource, and remediation priority."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        # Accept multiple parameter names: max_findings, count, page_size, limit
        final_count = count or max_findings or page_size or limit or 5
        final_count = min(max(1, final_count), 100)
        max_findings = final_count
        client = securitycenter.SecurityCenterClient()
        findings = client.list_findings(request={
            "parent": f"projects/{project_id}/sources/-",
            "filter": 'state="ACTIVE" AND findingClass="VULNERABILITY"',
        })
        results = []
        for f in findings:
            attack_exposure = f.finding.attack_exposure if hasattr(f.finding, 'attack_exposure') else None
            score = 0.0
            if attack_exposure and hasattr(attack_exposure, 'attack_exposure_score'):
                score = attack_exposure.attack_exposure_score or 0.0
            results.append({
                "name": f.finding.name,
                "category": f.finding.category,
                "severity": str(f.finding.severity),
                "resource": f.finding.resource_name,
                "attack_exposure_score": score,
                "create_time": str(f.finding.create_time),
                "external_uri": f.finding.external_uri,
                "description": (f.finding.description or "")[:500],
                "next_steps": (f.finding.next_steps or "")[:500] if hasattr(f.finding, 'next_steps') else "",
            })
        # Sort by attack exposure score descending
        results.sort(key=lambda x: x["attack_exposure_score"], reverse=True)
        results = results[:max_findings]
        logger.info(f"SCC vulnerabilities: {len(results)} findings for {project_id}")
        return json.dumps({"vulnerability_findings": results, "count": len(results), "project_id": project_id})
    except (PermissionDenied, NotFound, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_finding_remediation(project_id: str = "", finding_id: str = "") -> str:
    """Get detailed remediation guidance for a specific SCC finding. Returns next steps, affected resource context, and Cloud Asset Inventory info if available."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        if not finding_id:
            return json.dumps({"error": "finding_id is required"})
        client = securitycenter.SecurityCenterClient()
        # finding_id can be a full resource name or just the ID
        if not finding_id.startswith("organizations/") and not finding_id.startswith("projects/"):
            finding_name = f"projects/{project_id}/sources/-/findings/{finding_id}"
        else:
            finding_name = finding_id
        finding = client.get_finding(request={"name": finding_name})
        result = {
            "finding_id": finding.name,
            "category": finding.category,
            "severity": str(finding.severity),
            "state": str(finding.state),
            "resource_name": finding.resource_name,
            "description": finding.description or "",
            "external_uri": finding.external_uri,
            "create_time": str(finding.create_time),
            "next_steps": finding.next_steps if hasattr(finding, 'next_steps') else "",
            "source_properties": dict(finding.source_properties) if finding.source_properties else {},
        }
        # Try to get Cloud Asset Inventory context
        try:
            token = get_adc_token()
            asset_resp = requests.get(
                f"https://cloudasset.googleapis.com/v1/{finding.resource_name}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if asset_resp.status_code == 200:
                result["asset_context"] = asset_resp.json()
        except Exception:
            result["asset_context"] = "Unable to retrieve asset context"
        return json.dumps(result)
    except (PermissionDenied, NotFound, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📂 SOAR CASES & ALERTS (Extended)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_cases() -> str:
    """List all SOAR cases from Siemplify. Returns case IDs, titles, priorities, and statuses."""
    try:
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/GetCaseCardsByRequest",
            headers=_siemplify_headers(),
            json={"pageSize": 100, "pageNumber": 0},
            timeout=30,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            cases_raw = data.get("caseCards", data if isinstance(data, list) else [])
            formatted = []
            for c in cases_raw:
                formatted.append({
                    "id": c.get("id", ""),
                    "title": c.get("title", ""),
                    "priority": _SIEMPLIFY_PRIORITY_INV.get(c.get("priority"), str(c.get("priority", ""))),
                    "status": c.get("status", ""),
                    "stage": c.get("stage", ""),
                    "creation_time": c.get("creationTimeUnixTimeInMs", ""),
                    "assignee": c.get("assignedUserName", ""),
                })
            return json.dumps({"cases": formatted, "count": len(formatted)})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_case_alerts(case_id: str) -> str:
    """Get all alerts associated with a specific Siemplify SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.get(
            f"{SIEMPLIFY_BASE}/cases/GetCaseFullDetails/{case_id}",
            headers=_siemplify_headers(),
            timeout=30,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            alerts = data.get("alerts", data.get("alertsData", []))
            if not isinstance(alerts, list):
                alerts = []
            formatted = []
            for a in alerts:
                formatted.append({
                    "id": a.get("id", a.get("identifier", "")),
                    "rule_name": a.get("ruleName", a.get("name", a.get("alertDisplayName", ""))),
                    "severity": a.get("severity", ""),
                    "creation_time": a.get("creationTimeUnixTimeInMs", ""),
                    "status": a.get("status", ""),
                    "description": (str(a.get("description", "")) or "")[:500],
                })
            return json.dumps({"case_id": case_id, "alerts": formatted, "count": len(formatted)})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def add_case_comment(case_id: str, comment: str) -> str:
    """Add a comment to a Siemplify SOAR case. Use for investigation notes, status updates, or escalation context."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        if not comment or len(comment.strip()) < 1:
            return json.dumps({"error": "comment is required"})
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/comments",
            headers=_siemplify_headers(),
            json={"caseId": int(case_id), "comment": comment},
            timeout=15,
            verify=False,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Comment added to Siemplify case {case_id}")
            return json.dumps({"status": "comment_added", "case_id": case_id, "comment_length": len(comment)})
        return json.dumps({"error": f"Add comment failed [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📜 CLOUD LOGGING
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_recent_logs(count: int = 10, n: int = 0, source: str = "both") -> str:
    """Get the last N log entries from Cloud Logging AND/OR SecOps Chronicle UDM. Source: 'cloud', 'secops', or 'both' (default). Use for: 'last 10 logs', 'recent logs', 'show me logs'."""
    for val in [n]:
        if val > 0:
            count = val
            break
    count = min(max(1, count), 100)
    result = {}

    # ── Cloud Logging ──
    if source in ("both", "cloud", "gcp", "cloudlogging"):
        try:
            token = get_adc_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            resp = requests.post(
                "https://logging.googleapis.com/v2/entries:list",
                headers=headers,
                json={
                    "resourceNames": [f"projects/{SECOPS_PROJECT_ID}"],
                    "filter": "severity >= DEFAULT",
                    "orderBy": "timestamp desc",
                    "pageSize": count,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                entries = resp.json().get("entries", [])
                result["cloud_logging"] = [
                    {
                        "timestamp": e.get("timestamp", ""),
                        "severity": e.get("severity", "DEFAULT"),
                        "log_name": e.get("logName", "").split("/")[-1],
                        "resource_type": e.get("resource", {}).get("type", ""),
                        "message": (
                            e.get("textPayload")
                            or str(e.get("jsonPayload", e.get("protoPayload", "")))
                        )[:300],
                    }
                    for e in entries[:count]
                ]
            else:
                result["cloud_logging"] = {"error": f"Cloud Logging [{resp.status_code}]"}
        except Exception as ex:
            result["cloud_logging"] = {"error": str(ex)}

    # ── SecOps Chronicle UDM ──
    if source in ("both", "secops", "chronicle", "udm"):
        try:
            now = datetime.now(timezone.utc)
            start_dt = now - timedelta(hours=24)
            client = SecOpsClient()
            chronicle = client.chronicle(
                customer_id=SECOPS_CUSTOMER_ID,
                project_id=SECOPS_PROJECT_ID,
                region=SECOPS_REGION,
            )
            res = chronicle.search_udm(
                query='metadata.event_type != ""',
                start_time=start_dt,
                end_time=now,
                max_events=count,
            )
            events = res.get("events", []) if isinstance(res, dict) else (res if isinstance(res, list) else [])
            result["secops_udm"] = [
                {
                    "timestamp": e.get("udm", {}).get("metadata", {}).get("eventTimestamp", ""),
                    "event_type": e.get("udm", {}).get("metadata", {}).get("eventType", ""),
                    "product": e.get("udm", {}).get("metadata", {}).get("productName", ""),
                    "principal": e.get("udm", {}).get("principal", {}).get("hostname", e.get("udm", {}).get("principal", {}).get("ip", "")),
                    "target": e.get("udm", {}).get("target", {}).get("hostname", e.get("udm", {}).get("target", {}).get("ip", "")),
                }
                for e in events[:count]
            ]
        except Exception as ex:
            result["secops_udm"] = {"error": str(ex)}

    return json.dumps({"count_requested": count, "sources": result})


@app_mcp.tool()
def list_log_entries(project_id: str = "", filter_string: str = "", query: str = "", order_by: str = "timestamp desc", page_size: int = 20, limit: int = 0) -> str:
    """Query Cloud Logging entries using Log Query Language (LQL). Supports SIEM audit logs, SOAR playbook errors, IAM changes, and any GCP service logs."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        # Accept both filter_string and query params
        final_filter = filter_string or query
        if not final_filter or len(final_filter.strip()) < 3:
            final_filter = "severity >= DEFAULT"
        filter_string = final_filter
        if limit > 0:
            page_size = limit
        page_size = min(max(1, page_size), 1000)
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": filter_string,
            "orderBy": order_by,
            "pageSize": page_size,
        }
        resp = requests.post(
            "https://logging.googleapis.com/v2/entries:list",
            headers=headers,
            json=body,
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries", [])
            logger.info(f"Cloud Logging: {len(entries)} entries for {project_id}")
            return json.dumps({"entries": entries, "count": len(entries)})
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_log_names(project_id: str = "") -> str:
    """List all available log names in a GCP project. Useful for discovering what log sources exist before querying."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        client = cloud_logging.Client(project=project_id)
        # list_entries with a broad filter to discover log names
        entries = client.list_entries(
            filter_='timestamp >= "2026-01-01T00:00:00Z"',
            max_results=200,
            page_size=200,
        )
        log_names = sorted(set(e.log_name.split('/')[-1] for e in entries if e.log_name))
        logger.info(f"Cloud Logging: {len(log_names)} log names for {project_id}")
        return json.dumps({"log_names": log_names, "count": len(log_names)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_log_buckets(project_id: str = "") -> str:
    """List all Cloud Logging storage buckets and their retention policies."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"https://logging.googleapis.com/v2/projects/{project_id}/locations/-/buckets",
            headers=headers,
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            buckets = data.get("buckets", [])
            logger.info(f"Cloud Logging: {len(buckets)} buckets for {project_id}")
            return json.dumps({"buckets": buckets, "count": len(buckets)})
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_log_bucket(bucket_id: str = "_Default", project_id: str = "", location: str = "global") -> str:
    """Get details of a specific Cloud Logging bucket including retention period and lifecycle state."""
    try:
        project_id = validate_project_id(project_id)
        if not bucket_id:
            return json.dumps({"error": "bucket_id is required"})
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"https://logging.googleapis.com/v2/projects/{project_id}/locations/{location}/buckets/{bucket_id}",
            headers=headers,
            timeout=120,
        )
        if resp.status_code == 200:
            logger.info(f"Cloud Logging: bucket {bucket_id} details for {project_id}")
            return json.dumps(resp.json())
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_log_views(project_id: str = "", bucket_id: str = "_Default", location: str = "global") -> str:
    """List log views within a Cloud Logging bucket. Views control access to subsets of log data."""
    try:
        project_id = validate_project_id(project_id or SECOPS_PROJECT_ID)
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"https://logging.googleapis.com/v2/projects/{project_id}/locations/{location}/buckets/{bucket_id}/views",
            headers=headers,
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            views = data.get("views", [])
            logger.info(f"Cloud Logging: {len(views)} views for bucket {bucket_id}")
            return json.dumps({"views": views, "count": len(views)})
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def query_secops_audit_logs(project_id: str = "", hours_back: int = 24, log_type: str = "siem") -> str:
    """Query SecOps SIEM or SOAR audit logs from Cloud Logging. Finds rule errors, playbook failures, feed issues, and user activity."""
    try:
        project_id = validate_project_id(project_id)
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if log_type == "soar":
            filter_string = (
                f'severity="ERROR" AND logName="projects/{project_id}/logs/soar-logs"'
                f' AND timestamp >= "{start_time}"'
            )
        else:
            filter_string = (
                f'severity="ERROR" AND resource.labels.service="chronicle.googleapis.com"'
                f' AND timestamp >= "{start_time}"'
            )
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = {
            "resourceNames": [f"projects/{project_id}"],
            "filter": filter_string,
            "orderBy": "timestamp desc",
            "pageSize": 100,
        }
        resp = requests.post(
            "https://logging.googleapis.com/v2/entries:list",
            headers=headers,
            json=body,
            timeout=120,
        )
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries", [])
            logger.info(f"SecOps audit logs ({log_type}): {len(entries)} entries for {project_id}")
            return json.dumps({"log_type": log_type, "filter": filter_string, "entries": entries, "count": len(entries)})
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔐 RBAC & ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_data_access_labels(project_id: str = "") -> str:
    """List all data access labels (RBAC) configured in SecOps. Shows who can access what data."""
    try:
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/dataAccessLabels",
            headers=_secops_headers(),
            timeout=120,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_data_access_scopes(project_id: str = "") -> str:
    """List all data access scopes (RBAC) in SecOps. Shows permission boundaries for users and roles."""
    try:
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/dataAccessScopes",
            headers=_secops_headers(),
            timeout=120,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔧 PARSERS & PARSING
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_parsers(project_id: str = "") -> str:
    """List all configured parsers and log types in SecOps. Shows which log sources have active parsers."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_parsers()
        parsers = result if isinstance(result, list) else result.get('parsers', result)
        return json.dumps({"parsers": parsers, "count": len(parsers) if isinstance(parsers, list) else 0})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def validate_parser(log_type: str = "", raw_log_sample: str = "", project_id: str = "") -> str:
    """Validate a parser against a raw log sample. Tests if a log will parse correctly before deployment."""
    try:
        if not log_type:
            return json.dumps({"error": "log_type is required"})
        if not raw_log_sample:
            return json.dumps({"error": "raw_log_sample is required"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.post(
            f"{v1_base}/parsers:validateParser",
            headers=_secops_headers(),
            json={"logType": log_type, "rawLog": raw_log_sample},
            timeout=120,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📡 FEEDS & INGESTION
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_feeds(project_id: str = "") -> str:
    """List all configured data feeds in SecOps. Shows feed status, type, and last poll time."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_feeds()
        feeds = result if isinstance(result, list) else result.get('feeds', result)
        return json.dumps({"feeds": feeds, "count": len(feeds) if isinstance(feeds, list) else 0})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_feed(feed_id: str, project_id: str = "") -> str:
    """Get details of a specific feed including its configuration, status, and last ingestion time."""
    try:
        if not feed_id:
            return json.dumps({"error": "feed_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.get_feed(feed_id)
        return json.dumps(result if isinstance(result, dict) else {"feed": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📊 INGESTION METRICS
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def query_ingestion_stats(hours_back: int = 24) -> str:
    """Query ingestion volume statistics by log source. Shows total events ingested per log type."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.search_udm(
            query='metadata.event_type = "USER_LOGIN" OR metadata.event_type = "NETWORK_CONNECTION" OR metadata.event_type = "PROCESS_LAUNCH" OR metadata.event_type = "FILE_CREATION"',
            start_time=start_dt,
            end_time=now,
            max_events=10000,
        )
        events = result.get('events', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        # Aggregate by log type
        log_types = {}
        event_types = {}
        for e in events:
            if isinstance(e, dict):
                lt = e.get('metadata', {}).get('log_type', 'UNKNOWN')
                et = e.get('metadata', {}).get('event_type', 'UNKNOWN')
                log_types[lt] = log_types.get(lt, 0) + 1
                event_types[et] = event_types.get(et, 0) + 1
        sorted_lt = sorted(log_types.items(), key=lambda x: x[1], reverse=True)
        return json.dumps({
            "total_events_sampled": len(events),
            "hours_back": hours_back,
            "by_log_type": dict(sorted_lt[:20]),
            "by_event_type": dict(sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:10]),
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ RULE MANAGEMENT (expanded)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def create_rule(rule_text: str) -> str:
    """Create a new YARA-L detection rule in SecOps."""
    try:
        if not rule_text or len(rule_text.strip()) < 10:
            return json.dumps({"error": "rule_text is required and must be a valid YARA-L rule"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.post(
            f"{v1_base}/rules",
            headers=_secops_headers(),
            json={"text": rule_text},
            timeout=120,
        )
        if resp.status_code in (200, 201):
            logger.info("YARA-L rule created successfully")
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_rule(rule_id: str) -> str:
    """Get a specific YARA-L rule including its text, metadata, compilation state, and deployment status."""
    try:
        if not rule_id:
            return json.dumps({"error": "rule_id is required"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/rules/{rule_id}",
            headers=_secops_headers(),
            timeout=120,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_rule_errors(rule_id: str) -> str:
    """List errors for a specific YARA-L rule. Shows compilation failures, timeout errors, and execution issues."""
    try:
        if not rule_id:
            return json.dumps({"error": "rule_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_errors(rule_id)
        return json.dumps(result if isinstance(result, dict) else {"errors": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📂 CASE MANAGEMENT (expanded)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_case_comments(case_id: str, page_size: int = 50) -> str:
    """List all comments for a Siemplify SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.get(
            f"{SIEMPLIFY_BASE}/cases/comments",
            headers=_siemplify_headers(),
            params={"CaseId": case_id},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            comments = data if isinstance(data, list) else data.get("comments", data.get("data", []))
            return json.dumps({"case_id": case_id, "comments": comments[:page_size], "count": len(comments)})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_case_priority(case_id: str, priority: str) -> str:
    """Update the priority of a Siemplify SOAR case. Priority options: CRITICAL, HIGH, MEDIUM, LOW, INFO."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/ChangeCasePriority",
            headers=_siemplify_headers(),
            json={"caseId": int(case_id), "priority": _SIEMPLIFY_PRIORITY.get(priority.upper(), 60)},
            timeout=15,
            verify=False,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Siemplify case {case_id} priority updated to {priority}")
            return json.dumps({"status": "updated", "case_id": case_id, "priority": priority})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def close_case(case_id: str, reason: str = "Resolved") -> str:
    """Close a Siemplify SOAR case with a resolution reason."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/CloseCase",
            headers=_siemplify_headers(),
            json={"caseId": int(case_id), "rootCause": reason, "comment": reason},
            timeout=15,
            verify=False,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Siemplify case {case_id} closed: {reason}")
            return json.dumps({"status": "closed", "case_id": case_id, "reason": reason})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📈 DASHBOARDS / OVERVIEW
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_case_overview() -> str:
    """Get Siemplify SOAR case overview: total cases, open vs closed, by priority, by status."""
    try:
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/GetCaseCardsByRequest",
            headers=_siemplify_headers(),
            json={"pageSize": 200, "pageNumber": 0},
            timeout=30,
            verify=False,
        )
        if resp.status_code != 200:
            return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:300]})
        data = resp.json()
        cases = data.get("caseCards", data if isinstance(data, list) else [])
        stats = {"total": len(cases), "by_status": {}, "by_priority": {}}
        for c in cases:
            status = str(c.get("status", "UNKNOWN"))
            priority = _SIEMPLIFY_PRIORITY_INV.get(c.get("priority"), str(c.get("priority", "UNKNOWN")))
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            stats["by_priority"][priority] = stats["by_priority"].get(priority, 0) + 1
        return json.dumps({"overview": stats})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📒 SOAR PLAYBOOK MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_playbooks(page_size: int = 50) -> str:
    """List all Siemplify SOAR playbooks. Shows playbook names and enabled status."""
    try:
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/playbooks/GetEnabledWFCards",
            headers=_siemplify_headers(),
            json={},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            playbooks = data if isinstance(data, list) else data.get("playbooks", data.get("data", []))
            return json.dumps({"playbooks": playbooks[:page_size], "count": len(playbooks)})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_playbook(playbook_id: str) -> str:
    """Get details of a specific Siemplify SOAR playbook including its steps, triggers, and configuration."""
    try:
        if not playbook_id:
            return json.dumps({"error": "playbook_id is required"})
        resp = requests.get(
            f"{SIEMPLIFY_BASE}/playbooks/GetWorkflowFullInfoByIdentifier/{playbook_id}",
            headers=_siemplify_headers(),
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def create_playbook(
    name: str,
    description: str = "",
    trigger_type: str = "ALERT",
    trigger_filter: str = "",
    enabled: bool = True,
) -> str:
    """
    Create a new SOAR playbook in SecOps.
    
    Args:
        name: Playbook name (e.g., "Auto_Containment_IP")
        description: What the playbook does
        trigger_type: "ALERT", "CASE", "MANUAL", or "SCHEDULED"
        trigger_filter: Rule name or alert filter that triggers this playbook
        enabled: Whether the playbook is active
    """
    try:
        if not name:
            return json.dumps({"error": "Playbook name is required"})
        
        playbook_body = {
            "displayName": name,
            "description": description or f"Auto-generated playbook: {name}",
            "enabled": enabled,
            "trigger": {
                "triggerType": trigger_type,
            },
        }
        if trigger_filter:
            playbook_body["trigger"]["filter"] = trigger_filter
        
        resp = requests.post(
            f"{SECOPS_BASE_URL}/playbooks",
            headers=_secops_headers(),
            json=playbook_body,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Playbook created: {name}")
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def create_containment_playbook(
    threat_type: str = "ip",
    severity_threshold: str = "CRITICAL",
) -> str:
    """
    Create a pre-built containment playbook template for a specific threat type.
    Generates a playbook that triggers on auto-generated rules and executes containment.
    
    Args:
        threat_type: "ip", "domain", "hash", or "phishing"
        severity_threshold: Minimum severity to trigger — "HIGH" or "CRITICAL"
    """
    try:
        templates = {
            "ip": {
                "name": "Auto_Containment_Malicious_IP",
                "description": (
                    "Autonomous containment playbook for malicious IPs. "
                    "Triggered by Auto_IOC_IP_* rules. "
                    "Actions: 1) Enrich IP via GTI 2) If malicious >= 5: add to blocklist Data Table "
                    "3) Search for affected hosts 4) Queue CrowdStrike isolation (requires approval) "
                    "5) Add investigation comment to case 6) Close case if fully contained."
                ),
                "trigger_filter": "rule_name STARTS_WITH 'Auto_IOC_IP_'",
                "steps": [
                    {"action": "enrich_indicator", "description": "Enrich IP via VirusTotal/GTI"},
                    {"action": "udm_search", "description": "Search for all events involving this IP"},
                    {"action": "update_data_table", "description": "Add IP to automated_blocklist Data Table"},
                    {"action": "isolate_crowdstrike_host", "description": "Isolate affected endpoints (requires approval)", "requires_approval": True},
                    {"action": "add_case_comment", "description": "Document investigation findings"},
                    {"action": "close_case", "description": "Close case with containment summary"},
                ],
            },
            "domain": {
                "name": "Auto_Containment_Malicious_Domain",
                "description": (
                    "Autonomous containment for malicious domains. "
                    "Triggered by Auto_IOC_Domain_* rules. "
                    "Actions: 1) Enrich domain 2) Add to blocklist 3) Find users who visited "
                    "4) Suspend affected users in Okta (requires approval) 5) Close case."
                ),
                "trigger_filter": "rule_name STARTS_WITH 'Auto_IOC_Domain_'",
                "steps": [
                    {"action": "enrich_indicator", "description": "Enrich domain via GTI"},
                    {"action": "get_domain_report", "description": "Get full domain reputation report"},
                    {"action": "udm_search", "description": "Find users who accessed this domain"},
                    {"action": "update_data_table", "description": "Add domain to blocklist Data Table"},
                    {"action": "suspend_okta_user", "description": "Suspend affected users (requires approval)", "requires_approval": True},
                    {"action": "add_case_comment", "description": "Document findings and actions"},
                ],
            },
            "hash": {
                "name": "Auto_Containment_Malicious_File",
                "description": (
                    "Autonomous containment for malicious file hashes. "
                    "Triggered by Auto_IOC_Hash_* rules. "
                    "Actions: 1) Get file report from VT 2) Search for hosts with this file "
                    "3) Isolate affected hosts 4) Add hash to blocklist 5) Close case."
                ),
                "trigger_filter": "rule_name STARTS_WITH 'Auto_IOC_Hash_'",
                "steps": [
                    {"action": "get_file_report", "description": "Full VirusTotal file analysis"},
                    {"action": "udm_search", "description": "Find all hosts that executed this file"},
                    {"action": "isolate_crowdstrike_host", "description": "Isolate infected endpoints (requires approval)", "requires_approval": True},
                    {"action": "update_data_table", "description": "Add hash to blocklist Data Table"},
                    {"action": "add_case_comment", "description": "Document findings"},
                    {"action": "close_case", "description": "Close case with containment summary"},
                ],
            },
            "phishing": {
                "name": "Auto_Phishing_Containment",
                "description": (
                    "Autonomous phishing containment pipeline. "
                    "Triggered by Inbound_Phishing_* rules. "
                    "Actions: 1) Extract Message-ID 2) Enrich URLs via VT "
                    "3) O365 Hard Purge from all inboxes 4) Check if user clicked "
                    "5) If clicked: suspend Okta + kill Azure AD sessions 6) Close case."
                ),
                "trigger_filter": "rule_name STARTS_WITH 'Inbound_Phishing_'",
                "steps": [
                    {"action": "enrich_indicator", "description": "Enrich phishing URLs via GTI"},
                    {"action": "purge_email_o365", "description": "Hard Delete email from all inboxes"},
                    {"action": "udm_search", "description": "Check if anyone clicked the link"},
                    {"action": "suspend_okta_user", "description": "Suspend users who clicked (requires approval)", "requires_approval": True},
                    {"action": "revoke_azure_ad_sessions", "description": "Revoke Azure AD sessions for clickers"},
                    {"action": "add_case_comment", "description": "Full forensic documentation"},
                    {"action": "close_case", "description": "Close with containment summary"},
                ],
            },
        }
        
        template = templates.get(threat_type)
        if not template:
            return json.dumps({"error": f"Unknown threat_type: {threat_type}. Use: ip, domain, hash, or phishing"})
        
        # Create the playbook via API
        playbook_body = {
            "displayName": template["name"],
            "description": template["description"],
            "enabled": True,
            "trigger": {
                "triggerType": "ALERT",
                "filter": template["trigger_filter"],
            },
        }
        
        resp = requests.post(
            f"{SECOPS_BASE_URL}/playbooks",
            headers=_secops_headers(),
            json=playbook_body,
            timeout=15,
        )
        
        result = {
            "playbook_name": template["name"],
            "threat_type": threat_type,
            "trigger_filter": template["trigger_filter"],
            "steps": template["steps"],
            "description": template["description"],
        }
        
        if resp.status_code in (200, 201):
            result["status"] = "created"
            result["playbook_id"] = resp.json().get("name", "unknown")
            logger.info(f"Containment playbook created: {template['name']}")
            results_actions = [s["description"] for s in template["steps"]]
            result["actions_in_order"] = results_actions
        else:
            result["status"] = "template_generated"
            result["api_response"] = f"API [{resp.status_code}]: {resp.text[:300]}"
            result["note"] = "Playbook template generated. If API creation failed, create manually in SecOps UI using the template above."
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def export_playbook_template(playbook_id: str) -> str:
    """Export an existing playbook as a JSON template. Use this to clone or modify playbooks programmatically. The pro move: create a playbook manually in the UI, export it here, modify the JSON, and POST it back as a new playbook."""
    try:
        if not playbook_id:
            return json.dumps({"error": "playbook_id is required"})
        resp = requests.get(
            f"{SECOPS_BASE_URL}/playbooks/{playbook_id}",
            headers=_secops_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            template = resp.json()
            # Remove instance-specific fields so it can be reused
            for field in ["name", "createTime", "updateTime", "revisionId"]:
                template.pop(field, None)
            return json.dumps({"template": template, "usage": "Modify this JSON and pass to create_playbook or POST to /playbooks endpoint"})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def clone_playbook(source_playbook_id: str, new_name: str, new_trigger_filter: str = "") -> str:
    """Clone an existing playbook with a new name and optionally a new trigger filter. The fastest way to create playbooks: build one in the UI, then clone it via API for different threat types."""
    try:
        if not source_playbook_id or not new_name:
            return json.dumps({"error": "source_playbook_id and new_name are required"})
        # Get the source playbook
        get_resp = requests.get(
            f"{SECOPS_BASE_URL}/playbooks/{source_playbook_id}",
            headers=_secops_headers(),
            timeout=15,
        )
        if get_resp.status_code != 200:
            return json.dumps({"error": f"Source playbook not found [{get_resp.status_code}]"})
        
        template = get_resp.json()
        # Remove instance-specific fields
        for field in ["name", "createTime", "updateTime", "revisionId"]:
            template.pop(field, None)
        
        template["displayName"] = new_name
        if new_trigger_filter and "trigger" in template:
            template["trigger"]["filter"] = new_trigger_filter
        
        # Create the new playbook
        create_resp = requests.post(
            f"{SECOPS_BASE_URL}/playbooks",
            headers=_secops_headers(),
            json=template,
            timeout=15,
        )
        if create_resp.status_code in (200, 201):
            logger.info(f"Playbook cloned: {new_name} from {source_playbook_id}")
            return json.dumps({"status": "cloned", "new_playbook": create_resp.json().get("name", "unknown"), "name": new_name})
        return json.dumps({"error": f"Clone failed [{create_resp.status_code}]", "detail": create_resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔧 HELPER: Fallback summary builder
# ═══════════════════════════════════════════════════════════════

def _build_basic_summary(trigger, trigger_type, severity, enrichment, step2, step5b, results):
    """Fallback summary when Vertex AI is unavailable."""
    lines = [
        f"🔍 AUTONOMOUS INVESTIGATION COMPLETE",
        f"",
        f"Trigger: {trigger_type.upper()} — {trigger}",
        f"Severity: {severity}",
        f"",
        f"📊 Enrichment:",
    ]
    if enrichment.get("malicious_count") is not None:
        lines.append(f"  VT Score: {enrichment.get('malicious_count', 'N/A')}/{enrichment.get('total_engines', 'N/A')} malicious")
    if enrichment.get("country"):
        lines.append(f"  Country: {enrichment.get('country', 'N/A')}")
    if enrichment.get("asn"):
        lines.append(f"  ASN: {enrichment.get('asn', 'N/A')}")
    if enrichment.get("result") == "NOT_FOUND":
        lines.append(f"  ⚠️ NOT IN VT DATABASE — Potential zero-day")
    lines.append(f"")
    lines.append(f"🔎 UDM Search: {step2.get('events_found', 0)} events found (72h window)")
    lines.append(f"")
    lines.append(f"⚡ Actions Taken:")
    if results["actions_taken"]:
        for action in results["actions_taken"]:
            lines.append(f"  ✅ {action}")
    else:
        lines.append(f"  ℹ️ No automated actions required (severity={severity})")
    if step5b.get("actions"):
        lines.append(f"")
        lines.append(f"🛡️ Containment:")
        for ca in step5b["actions"]:
            action_name = ca.get("action", "UNKNOWN")
            detail = ca.get("detail", "")
            if ca.get("requires_approval"):
                lines.append(f"  ⏳ {action_name}: {detail} (REQUIRES APPROVAL)")
            else:
                lines.append(f"  ✅ {action_name}: {detail}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# 🤖 AUTONOMOUS INVESTIGATION PIPELINE
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def autonomous_investigate(trigger: str = "", threat_actor: str = "", actor_name: str = "", query: str = "", trigger_type: str = "auto", project_id: str = "", auto_create_rule: bool = True, auto_create_case: bool = True) -> str:
    """Run a full autonomous threat investigation: threat intel → UDM hunt → YARA-L rule → detection. Pass the threat actor name or IOC as 'trigger'."""
    trigger = trigger or threat_actor or actor_name or query
    try:
        pid = project_id or SECOPS_PROJECT_ID
        
        # Step 1: Get threat intel from Gemini
        token = get_adc_token()
        gemini_url = f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent"
        
        gemini_resp = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "contents": [{
                    "role": "user",
                    "parts": [{
                        "text": f"Provide threat intelligence on {trigger}: (1) Known aliases (2) Primary TTPs (3) Known C2 infrastructure (4) Malware families used. Be specific."
                    }]
                }],
                "systemInstruction": {"parts": [{"text": "You are a threat intelligence analyst."}]}
            },
            timeout=120
        )
        
        threat_intel = ""
        if gemini_resp.status_code == 200:
            threat_intel = gemini_resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        
        # Step 2: Ask Gemini to generate UDM queries based on this intel
        gemini_resp2 = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "contents": [{
                    "role": "user",
                    "parts": [{
                        "text": f"""Based on this threat intel on {trigger}:
{threat_intel}

Generate 2-3 UDM/YARA-L queries to hunt for this activity in our logs.
Return ONLY the queries, one per line, starting with 'QUERY:'
Example format:
QUERY: principal.ip = "1.2.3.4"
QUERY: target.process.command_line contains "cmd.exe"
"""
                    }]
                }],
                "systemInstruction": {"parts": [{"text": "You are a UDM query expert. Generate practical queries."}]}
            },
            timeout=120
        )
        
        udm_queries = []
        if gemini_resp2.status_code == 200:
            resp_text = gemini_resp2.json()["candidates"][0]["content"]["parts"][0]["text"]
            for line in resp_text.split('\n'):
                if line.startswith('QUERY:'):
                    query = line.replace('QUERY:', '').strip()
                    if query:
                        udm_queries.append(query)
        
        # Step 3: Hunt UDM
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        all_events = []
        for query in udm_queries:
            try:
                search_resp = requests.get(
                    f"{SECOPS_BASE_URL}:udmSearch",
                    headers=_secops_headers(),
                    params={"query": query, "time_range.start_time": start, "time_range.end_time": end, "limit": 100},
                    timeout=60
                )
                if search_resp.status_code == 200:
                    all_events.extend(search_resp.json().get("events", []))
            except:
                pass
        
        # Step 4: Assessment & Rules
        severity = "CRITICAL" if len(all_events) > 50 else "HIGH" if len(all_events) > 10 else "MEDIUM" if len(all_events) > 0 else "LOW"
        
        rule_created = False
        if severity in ("HIGH", "CRITICAL") and auto_create_rule:
            try:
                safe_trigger = sanitize_rule_input(trigger)
                safe_severity = sanitize_rule_input(severity)
                rule_text = f"""rule Auto_{safe_trigger.replace(" ", "_")}_{datetime.now().strftime("%Y%m%d")} {{
  meta:
    author = "MCP Boss"
    description = "Auto-detect {safe_trigger} activity"
    severity = "{safe_severity}"
  events:
    $e.metadata.event_type in ("PROCESS_LAUNCH", "NETWORK_CONNECTION", "AUTH_ATTEMPT")
  condition:
    $e
}}"""
                create_resp = requests.post(
                    f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1/projects/{pid}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}/rules",
                    headers=_secops_headers(),
                    json={"text": rule_text},
                    timeout=15
                )
                rule_created = create_resp.status_code in (200, 201)
            except:
                pass
        
        # Step 5: Report (plain English, no JSON)
        report = f"""
THREAT INVESTIGATION: {trigger}

Severity: {severity}
Events Found: {len(all_events)} (last 30 days)

Threat Intelligence:
{threat_intel[:500]}

Hunting Performed:
- {len(udm_queries)} UDM queries executed
- {len(all_events)} suspicious events detected

Detection Rules:
{"DEPLOYED" if rule_created else "NOT DEPLOYED (low severity)"}

Next Steps:
1. Review findings
2. Check SOAR cases for details
3. Investigate source IPs and accounts

"""
        return report
    
    except Exception as e:
        return f"Investigation failed: {str(e)}"

@app_mcp.tool()
def secops_list_cases(limit: int = 100) -> str:
    """List all Siemplify SOAR cases. Returns case IDs, titles, and statuses."""
    try:
        limit = min(max(1, limit), 1000)
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/GetCaseCardsByRequest",
            headers=_siemplify_headers(),
            json={"pageSize": limit, "pageNumber": 0},
            timeout=30,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            cases = data.get("caseCards", data if isinstance(data, list) else [])
            return json.dumps({"count": len(cases), "cases": cases})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_get_case(case_id: str) -> str:
    """Get detailed information about a specific Siemplify SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.get(
            f"{SIEMPLIFY_BASE}/cases/GetCaseFullDetails/{case_id}",
            headers=_siemplify_headers(),
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_update_case(case_id: str, priority: str = "", status: str = "", comment: str = "") -> str:
    """Update a Siemplify SOAR case priority, status, or add a comment."""
    return update_soar_case(case_id=case_id, priority=priority, status=status, comment=comment)


@app_mcp.tool()
def secops_list_case_alerts(case_id: str, limit: int = 50) -> str:
    """List all alerts associated with a specific Siemplify SOAR case."""
    return get_case_alerts(case_id=case_id)


@app_mcp.tool()
def secops_get_case_alert(case_id: str, alert_id: str) -> str:
    """Get detailed information about a specific Siemplify alert."""
    try:
        if not case_id or not alert_id:
            return json.dumps({"error": "case_id and alert_id are required"})
        resp = requests.get(
            f"{SIEMPLIFY_BASE}/alerts/GetAlertById",
            headers=_siemplify_headers(),
            params={"alertId": alert_id, "caseId": case_id},
            timeout=15,
            verify=False,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_update_case_alert(case_id: str, alert_id: str, status: str = "", severity: str = "") -> str:
    """Update a Siemplify alert status or severity."""
    try:
        if not case_id or not alert_id:
            return json.dumps({"error": "case_id and alert_id are required"})
        body = {"caseId": int(case_id), "alertId": alert_id}
        if status:
            body["status"] = status
        if severity:
            body["severity"] = severity
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/alerts/ChangeAlertStatus",
            headers=_siemplify_headers(),
            json=body,
            timeout=15,
            verify=False,
        )
        if resp.status_code in (200, 201):
            return json.dumps({"status": "updated", "alert_id": alert_id})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_create_case_comment(case_id: str, comment_text: str = "", comment: str = "") -> str:
    """Add a comment to a SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        final_comment = comment_text or comment
        if not final_comment:
            return json.dumps({"error": "comment_text or comment is required"})
        # Use add_case_comment which is the existing working function
        return add_case_comment(case_id=case_id, comment=final_comment)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_list_case_comments(case_id: str, limit: int = 100) -> str:
    """List all comments for a specific SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        # Delegate to list_case_comments
        return list_case_comments(case_id=case_id, page_size=min(limit, 200))
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_execute_bulk_close_case(case_ids: list, reason: str = "Resolved", confirm: bool = False) -> str:
    """Bulk close multiple SOAR cases.

    Args:
        case_ids: List of case IDs to close
        reason: Closure reason
        confirm: Must be True to execute. Without confirmation, returns a preview of the action.
    """
    if not confirm:
        return json.dumps({"status": "confirmation_required", "action": "secops_execute_bulk_close_case",
            "target": f"{len(case_ids) if isinstance(case_ids, list) else 0} cases",
            "warning": f"This will bulk-close {len(case_ids) if isinstance(case_ids, list) else 0} SOAR cases with reason '{reason}'. Re-invoke with confirm=True to proceed."})
    try:
        if not case_ids or not isinstance(case_ids, list):
            return json.dumps({"error": "case_ids must be a non-empty list"})
        results = []
        for cid in case_ids:
            r = json.loads(close_case(case_id=str(cid), reason=reason))
            results.append({"case_id": cid, "result": r})
        return json.dumps({"closed": len(results), "results": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_execute_manual_action(case_id: str, action_name: str, action_parameters: dict = None) -> str:
    """Execute a named action on a SOAR case (e.g., enrich, contain, escalate)."""
    try:
        if not case_id or not action_name:
            return json.dumps({"error": "case_id and action_name are required"})
        # Route to appropriate tool based on action_name
        action_lower = action_name.lower()
        if "comment" in action_lower:
            return add_case_comment(case_id=case_id, comment=str(action_parameters or action_name))
        elif "close" in action_lower:
            return close_case(case_id=case_id, reason=str(action_parameters or "Manual close"))
        elif "priority" in action_lower:
            priority = (action_parameters or {}).get("priority", "HIGH") if isinstance(action_parameters, dict) else "HIGH"
            return update_case_priority(case_id=case_id, priority=priority)
        else:
            return json.dumps({"note": f"Action '{action_name}' acknowledged", "case_id": case_id, "parameters": action_parameters})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── BIGQUERY TOOLS (5 tools) — using google-cloud-bigquery directly ──

@app_mcp.tool()
def bigquery_list_dataset_ids(project_id: str = "", limit: int = 100) -> str:
    """List all BigQuery dataset IDs in a project."""
    try:
        from google.cloud import bigquery
        project_id = project_id or SECOPS_PROJECT_ID
        bq = bigquery.Client(project=project_id)
        datasets = list(bq.list_datasets(max_results=min(limit, 1000)))
        return json.dumps({"project_id": project_id, "datasets": [d.dataset_id for d in datasets], "count": len(datasets)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def bigquery_list_table_ids(project_id: str = "", dataset_id: str = "", limit: int = 100) -> str:
    """List all table IDs in a BigQuery dataset."""
    try:
        from google.cloud import bigquery
        project_id = project_id or SECOPS_PROJECT_ID
        if not dataset_id:
            return json.dumps({"error": "dataset_id is required"})
        bq = bigquery.Client(project=project_id)
        tables = list(bq.list_tables(dataset_id, max_results=min(limit, 1000)))
        return json.dumps({"dataset_id": dataset_id, "tables": [t.table_id for t in tables], "count": len(tables)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def bigquery_get_dataset_info(project_id: str = "", dataset_id: str = "") -> str:
    """Get metadata about a BigQuery dataset including description and location."""
    try:
        from google.cloud import bigquery
        project_id = project_id or SECOPS_PROJECT_ID
        if not dataset_id:
            return json.dumps({"error": "dataset_id is required"})
        bq = bigquery.Client(project=project_id)
        ds = bq.get_dataset(dataset_id)
        return json.dumps({"dataset_id": ds.dataset_id, "location": ds.location, "description": ds.description, "created": str(ds.created), "modified": str(ds.modified)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def bigquery_get_table_info(project_id: str = "", dataset_id: str = "", table_id: str = "") -> str:
    """Get schema and metadata for a BigQuery table."""
    try:
        from google.cloud import bigquery
        project_id = project_id or SECOPS_PROJECT_ID
        if not dataset_id or not table_id:
            return json.dumps({"error": "dataset_id and table_id are required"})
        bq = bigquery.Client(project=project_id)
        table = bq.get_table(f"{project_id}.{dataset_id}.{table_id}")
        schema = [{"name": f.name, "type": str(f.field_type), "mode": f.mode} for f in table.schema]
        return json.dumps({"table_id": table_id, "num_rows": table.num_rows, "schema": schema, "description": table.description})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def bigquery_execute_sql(query: str, project_id: str = "", max_results: int = 1000, dry_run: bool = False) -> str:
    """Execute a SQL query in BigQuery. Returns result rows and stats."""
    try:
        from google.cloud import bigquery
        project_id = project_id or SECOPS_PROJECT_ID
        if not query or len(query.strip()) < 5:
            return json.dumps({"error": "SQL query is required"})
        max_results = min(max(1, max_results), 100000)
        bq = bigquery.Client(project=project_id)
        job_config = bigquery.QueryJobConfig(dry_run=dry_run)
        job = bq.query(query, job_config=job_config)
        if dry_run:
            return json.dumps({"dry_run": True, "bytes_processed": job.total_bytes_processed})
        rows = list(job.result(max_results=max_results))
        return json.dumps({"rows": [dict(r) for r in rows], "count": len(rows), "bytes_processed": job.total_bytes_processed})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# RUN SERVER
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# STARLETTE APP WITH SSE TRANSPORT
# ═══════════════════════════════════════════════════════════════

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, StreamingResponse


async def health_check(request: StarletteRequest):
    health = {
        "status": "healthy",
        "server": "google-native-mcp",
        "version": "3.2.0",
        "tools": len(list(app_mcp._tool_manager.list_tools())),
        "project": SECOPS_PROJECT_ID,
        "region": SECOPS_REGION,
        "integrations": {
            "gti": bool(GTI_API_KEY),
            "o365": bool(O365_CLIENT_ID),
            "okta": bool(OKTA_DOMAIN),
            "azure_ad": bool(AZURE_AD_CLIENT_ID),
            "aws": bool(AWS_ACCESS_KEY_ID),
            "crowdstrike": bool(CS_CLIENT_ID),
        },
    }
    return JSONResponse(health)


from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http import StreamableHTTPServerTransport
from starlette.routing import Mount
from starlette.responses import Response
from starlette.staticfiles import StaticFiles

from mcp.server.transport_security import TransportSecuritySettings
import pathlib

# Parameter normalization mapping
# Maps common parameter name variations to expected function parameter names
PARAMETER_ALIASES = {
    # Count/limit/results aliases
    "count": ["max_findings", "max_results", "limit", "max_events"],
    "limit": ["max_findings", "max_results", "count", "max_events"],
    "max_results": ["count", "limit", "max_findings", "max_events"],
    "max_events": ["count", "limit", "max_results", "max_findings"],
    "max_findings": ["count", "limit", "max_results"],
    
    # Query/filter/text aliases
    "query": ["text", "filter", "udm_query", "filter_string"],
    "text": ["query", "filter", "udm_query", "filter_string"],
    "filter": ["query", "text", "udm_query", "filter_string"],
    "filter_string": ["query", "text", "filter", "udm_query"],
    "udm_query": ["query", "text", "filter", "filter_string"],
    
    # Indicator/value aliases
    "value": ["indicator", "ip", "domain"],
    "indicator": ["value", "ip", "domain"],
    "ip": ["value", "indicator", "domain"],
    "domain": ["value", "indicator", "ip"],
    
    # Time range aliases
    "time_range": ["timerange", "hours_back"],
    "timerange": ["time_range", "hours_back"],
    "hours_back": ["time_range", "timerange"],
}

def normalize_tool_parameters(tool_name: str, args: dict) -> dict:
    """Normalize tool parameters to handle parameter name variations from Gemini.
    Maps Gemini's guessed parameter names to actual function parameter names."""
    if not args:
        return args
    
    # Get the actual function signature
    tool = app_mcp._tool_manager._tools.get(tool_name)
    if not tool or not hasattr(tool, 'fn'):
        return args
    
    import inspect
    sig = inspect.signature(tool.fn)
    valid_params = set(sig.parameters.keys())
    
    # Common parameter name mappings (Gemini guess → actual)
    PARAM_MAP = {
        # UDM search
        "query_string": "query",
        "udm_query_string": "query",
        "search_query": "query",
        "project_id": None,  # Handled internally, drop it
        # Threat actors
        "actor_name": "threat_actor_name",
        "threat_actor": "threat_actor_name",
        "name": "threat_actor_name",
        # Time
        "time_range_hours": "hours_back",
        "lookback_hours": "hours_back",
        "days_back": "hours_back",  # Will multiply by 24 below
        # Events
        "max_results": "max_events",
        "limit": "max_events",
        "n": "max_events",
        "count": "max_events",
        # SCC
        "finding_category": "category",
        "severity": "severity_filter",
        # Cases
        "display_name": "displayName",
        "case_description": "description",
    }
    
    normalized = {}
    for k, v in args.items():
        if k in valid_params:
            normalized[k] = v
        elif k in PARAM_MAP:
            mapped = PARAM_MAP[k]
            if mapped is None:
                continue  # Drop this parameter
            if mapped in valid_params:
                # Handle days_back → hours_back conversion
                if k == "days_back" and mapped == "hours_back":
                    try:
                        v = int(v) * 24
                    except (ValueError, TypeError):
                        pass
                normalized[mapped] = v
        else:
            # Try fuzzy match: if the param name contains a valid param name
            matched = False
            for vp in valid_params:
                if vp in k or k in vp:
                    normalized[vp] = v
                    matched = True
                    break
            if not matched:
                # Pass it through — the function may accept **kwargs or have defaults
                normalized[k] = v
    
    return normalized

# Create SSE transport with security disabled for Cloud Run compatibility
# Cloud Run's load balancer forwards requests with different Host headers
# which triggers the default DNS rebinding protection
sse = SseServerTransport(
    "/messages/",
    security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


async def handle_sse(request: StarletteRequest):
    """SSE endpoint for MCP clients."""
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as (read_stream, write_stream):
        await app_mcp._mcp_server.run(
            read_stream,
            write_stream,
            app_mcp._mcp_server.create_initialization_options(),
        )
    return Response()


async def handle_mcp(request: StarletteRequest):
    """Streamable HTTP MCP endpoint — compatible with Gemini CLI and Claude Desktop."""
    transport = StreamableHTTPServerTransport(
        mcp_session_id=request.headers.get("mcp-session-id"),
        is_json_response_enabled=False,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    async with transport.connect() as (read_stream, write_stream):
        await app_mcp._mcp_server.run(
            read_stream,
            write_stream,
            app_mcp._mcp_server.create_initialization_options(),
        )
    return Response()


async def api_tools(request: StarletteRequest):
    """Return list of available tools as JSON for the web UI."""
    tool_list = []
    for tool in app_mcp._tool_manager.list_tools():
        tool_list.append({"name": tool.name, "description": tool.description or ""})
    return JSONResponse(tool_list)


async def api_chat_stream(request: StarletteRequest):
    """
    Streaming chat endpoint using Server-Sent Events (SSE).
    Handles multi-phase threat hunts without timeout.
    Sends real-time events: tool_selected -> tool_executing -> tool_result -> analyzing -> summary -> done
    """
    user_email = _verify_google_token(request)
    if not user_email:
        return JSONResponse({"error": "Unauthorized. Please sign in with Google."}, status_code=401)

    async def event_generator():
        try:
            body = await request.json()
            user_msg = body.get("message", "")
            if not user_msg:
                yield f"data: {json.dumps({'error': 'No message provided', 'type': 'error'})}\n\n"
                return

            # Session handling
            session_id = (
                body.get("session_id")
                or request.headers.get("x-session-id")
                or request.cookies.get("soc_session")
            )
            if not session_id:
                session_id = str(uuid.uuid4())
            session_store.get_or_create(session_id)

            yield f"data: {json.dumps({'type': 'session_id', 'session_id': session_id})}\n\n"
            await asyncio.sleep(0.01)  # Force chunk flush

            # Build tool declarations
            all_tools = app_mcp._tool_manager.list_tools()
            tool_declarations = []
            for tool in all_tools:
                properties = {}
                required = []
                if hasattr(tool, 'inputSchema'):
                    schema = tool.inputSchema
                    if isinstance(schema, dict):
                        properties = schema.get('properties', {})
                        required = schema.get('required', [])
                
                tool_declarations.append({
                    "name": tool.name,
                    "description": tool.description or "No description",
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                })

            token = get_adc_token()
            gemini_url = (
                f"https://us-central1-aiplatform.googleapis.com/v1/"
                f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
                f"publishers/google/models/{GEMINI_MODEL}:generateContent"
            )
            headers_ai = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            # Get conversation history + current message
            history = session_store.get_history(session_id)
            contents = history + [{"role": "user", "parts": [{"text": user_msg}]}]

            # Call Gemini with tool declarations
            gemini_resp = requests.post(
                gemini_url,
                headers=headers_ai,
                json={
                    "contents": contents,
                    "tools": [{"functionDeclarations": tool_declarations}],
                    "systemInstruction": {"parts": [{"text": (
                        "You are a security analyst. You have access to tools that can help investigate security events. "
                        "If the user's request requires a tool, call the appropriate tool with the right parameters. "
                        "If no tool is needed, answer directly. "
                        f"Default project_id is {SECOPS_PROJECT_ID} unless specified. "
                        "Remember context from earlier in this conversation. "
                        "Always provide clear reasoning for your actions."
                    )}]},
                },
                timeout=120,
            )

            if gemini_resp.status_code != 200:
                yield f"data: {json.dumps({'error': f'Gemini error: {gemini_resp.text[:300]}', 'type': 'error'})}\n\n"
                return

            response_data = gemini_resp.json()
            candidates = response_data.get("candidates", [])
            if not candidates:
                yield f"data: {json.dumps({'error': 'No response from Gemini', 'type': 'error'})}\n\n"
                return

            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            
            # Check if Gemini made a tool call
            tool_called = None
            tool_args = None
            tool_result_data = None
            summary = None
            
            for part in parts:
                if "functionCall" in part:
                    # Tool call detected
                    tool_called = part["functionCall"]["name"]
                    tool_args = part["functionCall"].get("args", {})
                    
                    # Send tool_selected event
                    yield f"data: {json.dumps({'type': 'tool_selected', 'tool': tool_called, 'args': tool_args})}\n\n"
                    await asyncio.sleep(0.01)
                    
                    try:
                        # Send tool_executing event
                        yield f"data: {json.dumps({'type': 'tool_executing', 'tool': tool_called})}\n\n"
                        await asyncio.sleep(0.01)
                        
                        # Execute tool
                        tool = app_mcp._tool_manager._tools.get(tool_called)
                        if not tool:
                            raise ValueError(f"Tool {tool_called} not found")
                        
                        normalized_args = normalize_tool_parameters(tool_called, tool_args)
                        result_text = tool.fn(**normalized_args)
                        
                        if not isinstance(result_text, str):
                            result_text = str(result_text)
                        
                        # Parse result
                        try:
                            tool_result_data = json.loads(result_text)
                        except (json.JSONDecodeError, TypeError):
                            if len(result_text) <= 2:
                                tool_result_data = {"error": f"Tool returned truncated result: {result_text}"}
                            else:
                                tool_result_data = result_text
                        
                        # Send tool_result event (chunked for large results)
                        result_preview = json.dumps(tool_result_data)[:2000] if isinstance(tool_result_data, dict) else str(tool_result_data)[:2000]
                        yield f"data: {json.dumps({'type': 'tool_result', 'preview': result_preview, 'full_size': len(str(tool_result_data))})}\n\n"
                        await asyncio.sleep(0.01)
                        
                        # Send analyzing event
                        yield f"data: {json.dumps({'type': 'analyzing', 'tool': tool_called})}\n\n"
                        await asyncio.sleep(0.01)
                        
                        # Generate summary
                        try:
                            sum_resp = requests.post(
                                gemini_url,
                                headers={"Authorization": f"Bearer {get_adc_token()}", "Content-Type": "application/json"},
                                json={
                                    "contents": [
                                        {"role": "user", "parts": [{"text": user_msg}]},
                                        {"role": "model", "parts": [{"text": f"I will call the {tool_called} tool with arguments {json.dumps(tool_args)}."}]},
                                        {"role": "user", "parts": [{"text": f"Here are the results from {tool_called}:\n\n{result_text[:5000]}\n\nPlease analyze and summarize the key findings. Be specific and actionable."}]},
                                    ],
                                    "systemInstruction": {"parts": [{"text": (
                                        "You are a security analyst summarizing tool results for a SOC operator. "
                                        "Be concise, highlight the most important findings, and recommend next steps. "
                                        "Do NOT ask for more information — you have everything you need in the tool output above."
                                    )}]},
                                },
                                timeout=60,
                            )
                            summary = sum_resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                        except Exception as e:
                            logger.error(f"Summary generation failed: {e}")
                            summary = f"Tool {tool_called} executed successfully. (Summary failed: {e})"
                        
                        # Send summary event
                        yield f"data: {json.dumps({'type': 'summary', 'text': summary})}\n\n"
                        await asyncio.sleep(0.01)
                        
                        # Update session history
                        session_store.append_history(session_id, "user", user_msg)
                        session_store.append_history(session_id, "model", f"[Called {tool_called}] {summary}")
                        
                        # Send done event
                        yield f"data: {json.dumps({'type': 'done', 'session_id': session_id, 'tool_called': tool_called})}\n\n"
                        await asyncio.sleep(0.01)
                        
                    except Exception as e:
                        logger.error(f"Tool execution error: {e}")
                        yield f"data: {json.dumps({'type': 'error', 'error': f'Tool execution failed: {str(e)}'})}\n\n"
                        await asyncio.sleep(0.01)
                
                elif "text" in part:
                    # Direct text response (no tool call)
                    text_response = part["text"]
                    session_store.append_history(session_id, "user", user_msg)
                    session_store.append_history(session_id, "model", text_response)
                    yield f"data: {json.dumps({'type': 'summary', 'text': text_response})}\n\n"
                    await asyncio.sleep(0.01)
                    yield f"data: {json.dumps({'type': 'done', 'session_id': session_id})}\n\n"
        
        except Exception as e:
            logger.error(f"Chat stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
            await asyncio.sleep(0.01)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def api_auth_config(request: StarletteRequest):
    return JSONResponse({"client_id": OAUTH_CLIENT_ID, "auth_required": bool(OAUTH_CLIENT_ID)})


def _verify_google_token(request: StarletteRequest) -> str | None:
    """Verify Google ID token. Returns email on success, None on failure. Skips check if OAUTH_CLIENT_ID not set."""
    if not OAUTH_CLIENT_ID:
        return "dev"
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        from google.oauth2 import id_token as gid_token
        from google.auth.transport import requests as g_requests
        info = gid_token.verify_oauth2_token(token, g_requests.Request(), OAUTH_CLIENT_ID)
        email = info.get("email", "")
        if ALLOWED_EMAILS and email not in ALLOWED_EMAILS:
            logger.warning(f"Auth rejected: {email} not in allowed list")
            return None
        return email
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None


async def api_chat(request: StarletteRequest):
    """
    Chat endpoint: Multi-turn orchestration loop.
    Feeds tool results (and errors) back to Claude so it can self-correct and chain tools.
    """
    user_email = _verify_google_token(request)
    if not user_email:
        return JSONResponse({"error": "Unauthorized. Please sign in with Google."}, status_code=401)

    try:
        body = await request.json()
        user_msg = body.get("message", "")
        if not user_msg:
            return JSONResponse({"error": "No message provided"}, status_code=400)

        session_id = body.get("session_id") or request.headers.get("x-session-id") or request.cookies.get("soc_session") or str(uuid.uuid4())
        session_store.get_or_create(session_id)

        # Build tool list (all tools minus internal session mgmt)
        all_tools = [t for t in app_mcp._tool_manager.list_tools() if t.name not in GEMINI_TOOL_EXCLUDE]
        claude_tools = []
        for tool in all_tools:
            properties = {}
            required = []
            if hasattr(tool, 'inputSchema') and isinstance(tool.inputSchema, dict):
                properties = tool.inputSchema.get('properties', {})
                required = tool.inputSchema.get('required', [])
            claude_tools.append({
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": {"type": "object", "properties": properties, "required": required}
            })

        # Convert stored Gemini-format history → Claude format
        raw_history = session_store.get_history(session_id)
        messages = []
        for h in raw_history:
            role = "assistant" if h.get("role") == "model" else h.get("role", "user")
            parts = h.get("parts", [])
            if isinstance(parts, list):
                text = " ".join(p.get("text", "") for p in parts if isinstance(p, dict) and "text" in p)
            else:
                text = str(parts)
            if text.strip():
                messages.append({"role": role, "content": text})
        messages.append({"role": "user", "content": user_msg})

        system_text = (
            "You are an elite security analyst orchestration engine with access to security tools.\n\n"
            "TOOL ROUTING — always call a tool, never answer security questions from memory:\n"
            "- 'search SecOps UDM / search UDM / search Chronicle / search logs' → search_secops_udm\n"
            "- 'failed logins / auth failures / login events' → search_security_events\n"
            "- 'last N logs / recent logs / show me logs / show logs' → get_recent_logs\n"
            "- 'enrich / lookup / check indicator / IP / domain / hash' → enrich_indicator or get_ip_report\n"
            "- 'investigate threat actor / APT / group' → search_threat_actors\n"
            "- 'SCC findings / vulnerabilities / misconfigs' → get_scc_findings\n"
            "- 'SOAR cases / incidents' → list_cases or get_last_cases\n"
            "- 'detections / alerts / rules fired' → list_secops_detections\n\n"
            "INVESTIGATION WORKFLOW — When asked to investigate a threat actor:\n"
            "1. Call search_threat_actors for GTI profile (IOCs, domains, IPs, hashes)\n"
            "2. Call search_secops_udm to hunt those IOCs in UDM logs\n"
            "3. Call get_scc_findings for cloud vulnerabilities\n"
            "4. Correlate and summarize\n\n"
            "RULES:\n"
            "- ALWAYS call a tool when the request is about security data — never refuse or answer from memory\n"
            "- For UDM searches: pass natural language in the query parameter — the tool handles translation\n"
            "- After 2-4 tool calls, STOP and write your final report\n"
            "- NEVER output raw JSON. Summarize in clear human-readable prose.\n"
            f"- Default project_id: {SECOPS_PROJECT_ID}\n"
        )

        max_turns = 8
        tool_execution_log = []
        final_text = ""

        # ── Try Claude on Vertex AI, fall back to Gemini if unavailable ──
        use_claude = bool(CLAUDE_MODEL)
        if use_claude:
            try:
                from anthropic import AnthropicVertex
                claude_client = AnthropicVertex(project_id=SECOPS_PROJECT_ID, region=CLAUDE_REGION)
                # Probe with a minimal call to detect availability early
                claude_client.messages.create(
                    model=CLAUDE_MODEL, max_tokens=1,
                    messages=[{"role": "user", "content": "ping"}],
                )
            except Exception as probe_err:
                logger.warning(f"Claude unavailable ({probe_err}), falling back to Gemini")
                use_claude = False

        if use_claude:
            from anthropic import AnthropicVertex
            claude_client = AnthropicVertex(project_id=SECOPS_PROJECT_ID, region=CLAUDE_REGION)

            for turn in range(max_turns):
                response = claude_client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=8096,
                    system=system_text,
                    tools=claude_tools,
                    messages=messages,
                )
                messages.append({"role": "assistant", "content": response.content})

                if response.stop_reason == "end_turn":
                    for block in response.content:
                        if hasattr(block, "text"):
                            final_text += block.text
                    break
                elif response.stop_reason == "tool_use":
                    tool_results = []
                    for block in response.content:
                        if block.type == "tool_use":
                            tool_name = block.name
                            tool_args = block.input or {}
                            try:
                                tool_obj = app_mcp._tool_manager._tools.get(tool_name)
                                if not tool_obj:
                                    result_text = f"Tool {tool_name} not found"
                                else:
                                    normalized_args = normalize_tool_parameters(tool_name, tool_args)
                                    result_text = tool_obj.fn(**normalized_args)
                                    if not isinstance(result_text, str):
                                        result_text = str(result_text)
                                tool_execution_log.append(f"⚡ {tool_name}({json.dumps(tool_args)})\nResult: {result_text[:500]}")
                                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result_text})
                            except Exception as e:
                                error_msg = f"Error executing {tool_name}: {str(e)}"
                                tool_execution_log.append(f"❌ {tool_name}\n{error_msg}")
                                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": error_msg, "is_error": True})
                    messages.append({"role": "user", "content": tool_results})
                else:
                    for block in response.content:
                        if hasattr(block, "text"):
                            final_text += block.text
                    break

        else:
            # ── Gemini fallback ──
            token = get_adc_token()
            gemini_url = f"https://us-central1-aiplatform.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}/locations/us-central1/publishers/google/models/{GEMINI_MODEL}:generateContent"
            headers_ai = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            gemini_tool_declarations = [{"name": t["name"], "description": t["description"], "parameters": t["input_schema"]} for t in claude_tools]
            # Convert Claude-format messages to Gemini format
            contents = []
            for m in messages:
                role = "model" if m["role"] == "assistant" else m["role"]
                content = m["content"]
                if isinstance(content, str):
                    contents.append({"role": role, "parts": [{"text": content}]})
                elif isinstance(content, list):
                    parts = [{"text": b.get("text", "") if isinstance(b, dict) else str(b)} for b in content]
                    contents.append({"role": role, "parts": parts})

            for turn in range(max_turns):
                g_resp = requests.post(
                    gemini_url, headers=headers_ai,
                    json={"contents": contents, "tools": [{"functionDeclarations": gemini_tool_declarations}],
                          "systemInstruction": {"parts": [{"text": system_text}]}},
                    timeout=120
                )
                if g_resp.status_code != 200:
                    return JSONResponse({"error": f"Gemini [{g_resp.status_code}]: {g_resp.text[:300]}"})
                candidates = g_resp.json().get("candidates", [])
                if not candidates:
                    break
                content_data = candidates[0].get("content", {})
                parts = content_data.get("parts", [])
                contents.append(content_data)
                has_tool_call = any("functionCall" in p for p in parts)
                if has_tool_call:
                    tool_responses = []
                    for part in parts:
                        if "functionCall" in part:
                            tool_name = part["functionCall"]["name"]
                            tool_args = part["functionCall"].get("args", {})
                            try:
                                tool_obj = app_mcp._tool_manager._tools.get(tool_name)
                                result_text = tool_obj.fn(**normalize_tool_parameters(tool_name, tool_args)) if tool_obj else f"Tool {tool_name} not found"
                                if not isinstance(result_text, str):
                                    result_text = str(result_text)
                                tool_execution_log.append(f"⚡ {tool_name}({json.dumps(tool_args)})\nResult: {result_text[:500]}")
                                tool_responses.append({"functionResponse": {"name": tool_name, "response": {"result": result_text}}})
                            except Exception as e:
                                tool_execution_log.append(f"❌ {tool_name}\n{e}")
                                tool_responses.append({"functionResponse": {"name": tool_name, "response": {"error": str(e)}}})
                    contents.append({"role": "user", "parts": tool_responses})
                else:
                    for part in parts:
                        if "text" in part:
                            final_text += part["text"] + "\n"
                    break

        log_preview = "\n\n".join(tool_execution_log)
        session_store.append_history(session_id, "user", user_msg)
        session_store.append_history(session_id, "model", final_text)

        resp = JSONResponse({
            "tool_called": "Multiple tools executed" if len(tool_execution_log) > 1 else (tool_execution_log[0].split("(")[0].replace("⚡ ", "") if tool_execution_log else None),
            "tool_result": "Orchestration complete",
            "raw_result_preview": log_preview,
            "response": final_text,
            "session_id": session_id,
        })
        resp.set_cookie("soc_session", session_id, max_age=86400, samesite="lax")
        return resp

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

# ═══════════════════════════════════════════════════════════════
# 📊 MTTx METRICS
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def get_mttx_metrics(
    hours_back: int = 8760,  # default 1 year
    priority_filter: str = "",
    include_open: bool = True,
    max_cases: int = 500,
) -> str:
    """
    Calculate SOC MTTx metrics from SOAR case data.

    Returns:
      - MTTD  (Mean Time to Detect)   — first alert event_time → case createTime
      - MTTR  (Mean Time to Respond)  — case createTime → first status change / updateTime
      - MTTC  (Mean Time to Contain)  — case createTime → CLOSED updateTime (closed cases only)
      - MTTP  (Mean Time to Prioritize) — case createTime → priority set (non-LOW)

    Args:
        hours_back:      Look-back window in hours (default 168 = 7 days)
        priority_filter: Filter by priority: CRITICAL, HIGH, MEDIUM, LOW (default: all)
        include_open:    Include open cases in MTTR/response stats
        max_cases:       Max cases to analyse (default 500)
    """
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )

        cutoff_ms = int((datetime.now(timezone.utc) - timedelta(hours=hours_back)).timestamp() * 1000)
        priority_upper = ""
        if priority_filter:
            p = priority_filter.upper()
            priority_upper = p if p.startswith("PRIORITY_") else f"PRIORITY_{p}"

        all_cases = []
        page_token = None
        fetched = 0
        while fetched < max_cases:
            kwargs = {"page_size": min(100, max_cases - fetched)}
            if page_token:
                kwargs["page_token"] = page_token
            result = chronicle.list_cases(**kwargs)
            page_cases = result.get("cases", []) if isinstance(result, dict) else []
            # Filter in Python: time window + priority
            for c in page_cases:
                ct = int(c.get("createTime", 0) or 0)
                if ct < cutoff_ms:
                    # Cases are ordered newest-first; once we go past the window, stop
                    page_token = None
                    break
                if priority_upper and c.get("priority", "") != priority_upper:
                    continue
                all_cases.append(c)
            fetched += len(page_cases)
            page_token = result.get("nextPageToken") if isinstance(result, dict) else None
            if not page_token or not page_cases:
                break

        def ms_to_dt(ms_str):
            try:
                return datetime.fromtimestamp(int(ms_str) / 1000, tz=timezone.utc)
            except Exception:
                return None

        def td_minutes(td):
            return round(td.total_seconds() / 60, 1) if td else None

        mttc_values = []  # closed cases only: createTime → updateTime
        mttr_values = []  # all cases: createTime → updateTime (first touch)
        by_priority = {}
        by_status = {"OPENED": 0, "CLOSED": 0, "OTHER": 0}
        escalation_counts = {"PRIORITY_CRITICAL": 0, "PRIORITY_HIGH": 0, "PRIORITY_MEDIUM": 0, "PRIORITY_LOW": 0}

        for case in all_cases:
            create_dt = ms_to_dt(case.get("createTime", 0))
            update_dt = ms_to_dt(case.get("updateTime", 0))
            status = case.get("status", "UNKNOWN")
            priority = case.get("priority", "UNKNOWN")

            # Status counts
            if status == "OPENED":
                by_status["OPENED"] += 1
            elif status == "CLOSED":
                by_status["CLOSED"] += 1
            else:
                by_status["OTHER"] += 1

            # Priority counts
            escalation_counts[priority] = escalation_counts.get(priority, 0) + 1

            if create_dt and update_dt and update_dt > create_dt:
                delta_min = td_minutes(update_dt - create_dt)
                if delta_min is not None:
                    mttr_values.append(delta_min)
                    if status == "CLOSED":
                        mttc_values.append(delta_min)

                # By priority breakdown
                p_key = priority.replace("PRIORITY_", "")
                if p_key not in by_priority:
                    by_priority[p_key] = []
                by_priority[p_key].append(delta_min)

        def stats(values):
            if not values:
                return {"count": 0, "mean_min": None, "median_min": None, "p90_min": None}
            s = sorted(values)
            n = len(s)
            mean = round(sum(s) / n, 1)
            median = s[n // 2]
            p90 = s[int(n * 0.9)]
            return {"count": n, "mean_min": mean, "median_min": median, "p90_min": p90,
                    "mean_hr": round(mean / 60, 2), "median_hr": round(median / 60, 2)}

        priority_stats = {p: stats(v) for p, v in by_priority.items()}

        return json.dumps({
            "window_hours": hours_back,
            "total_cases_analyzed": len(all_cases),
            "case_status_breakdown": by_status,
            "case_priority_breakdown": escalation_counts,
            "metrics": {
                "MTTR": {
                    "description": "Mean Time to Respond — case open to first update (all cases)",
                    **stats(mttr_values)
                },
                "MTTC": {
                    "description": "Mean Time to Close — case open to close (closed cases only)",
                    **stats(mttc_values)
                },
            },
            "by_priority": priority_stats,
            "note": "MTTD requires alert event_time data; use search_secops_udm to correlate alert timestamps for full MTTD calculation."
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


STATIC_DIR = pathlib.Path(__file__).parent / "static"

# ═══════════════════════════════════════════════════════════════
# 🔗 GEMINI CLI MCP SERVER (focused 20-tool subset)
# Gemini API can't handle 86 tools — expose a focused subset
# ═══════════════════════════════════════════════════════════════

# Expose ALL 86 tools to Gemini — no artificial restrictions.
# Only exclude internal/session management tools that shouldn't be called by the LLM.
GEMINI_TOOL_EXCLUDE = {
    "create_session", "get_session", "set_session_context",  # internal session mgmt
}
GEMINI_TOOL_ALLOWLIST = None  # Signal to use all tools minus exclusions

app_mcp_gemini = FastMCP("google-soc", json_response=True)

# Register all tools except excluded internal ones
_gemini_tool_count = 0
for _tool in app_mcp._tool_manager.list_tools():
    if _tool.name not in GEMINI_TOOL_EXCLUDE:
        app_mcp_gemini._tool_manager._tools[_tool.name] = _tool
        _gemini_tool_count += 1

logger.info(f"Gemini MCP server: {_gemini_tool_count} tools exposed (all minus {len(GEMINI_TOOL_EXCLUDE)} excluded)")

# Streamable HTTP for Gemini CLI using StreamableHTTPSessionManager with proper lifespan
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from contextlib import asynccontextmanager
import anyio

_session_manager = StreamableHTTPSessionManager(
    app=app_mcp_gemini._mcp_server,
    event_store=None,
    stateless=True,
    security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

@asynccontextmanager
async def lifespan(starlette_app):
    async with _session_manager.run():
        yield

class MCPMiddleware:
    """ASGI middleware that intercepts /mcp requests for Gemini CLI / Claude Desktop."""
    def __init__(self, starlette_app):
        self.app = starlette_app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http' and scope.get('path', '') == '/mcp':
            await _session_manager.handle_request(scope, receive, send)
        else:
            await self.app(scope, receive, send)

_starlette_app = Starlette(
    lifespan=lifespan,
    routes=[
        Route("/health", endpoint=health_check),
        Route("/api/auth-config", endpoint=api_auth_config),
        Route("/api/tools", endpoint=api_tools),
        Route("/api/chat", endpoint=api_chat, methods=["POST"]),
        Route("/api/chat/stream", endpoint=api_chat_stream, methods=["POST"]),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
        Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True)),
    ]
)


class SecurityHeadersMiddleware:
    """Adds security headers to every response."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"x-content-type-options"] = b"nosniff"
                headers[b"x-frame-options"] = b"DENY"
                headers[b"x-xss-protection"] = b"1; mode=block"
                headers[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                headers[b"referrer-policy"] = b"strict-origin-when-cross-origin"
                headers[b"permissions-policy"] = b"camera=(), microphone=(), geolocation=(), payment=()"
                headers[b"cross-origin-opener-policy"] = b"same-origin-allow-popups"
                headers[b"cross-origin-resource-policy"] = b"same-origin"
                headers[b"server"] = b"mcp-boss"
                headers[b"content-security-policy"] = (
                    b"default-src 'self'; "
                    b"script-src 'self' 'unsafe-inline' https://accounts.google.com; "
                    b"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    b"font-src 'self' https://fonts.gstatic.com; "
                    b"img-src 'self' data: https:; "
                    b"connect-src 'self'; "
                    b"frame-src https://accounts.google.com; "
                    b"frame-ancestors 'none';"
                )
                message = dict(message)
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)


app = SecurityHeadersMiddleware(MCPMiddleware(_starlette_app))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8080")))


@app_mcp.tool()
def create_detection_rule_for_scc_finding(finding_category: str, resource: str = "", severity: str = "HIGH") -> str:
    """Create a YARA-L detection rule based on an SCC finding category.
    
    Examples:
    - "Privilege Escalation: Impersonation Role Granted" → rule detecting service account impersonation
    - "User-managed keys to service account" → rule detecting key creation events
    - "Persistence: IAM Anomalous Grant" → rule detecting unusual IAM grants
    """
    try:
        finding_category = sanitize_rule_input(finding_category)
        severity = sanitize_rule_input(severity)

        # Generate rule name from category
        rule_name = finding_category.replace(" ", "_").replace(":", "").replace("-", "_")[:60]
        rule_name = f"SCC_{rule_name}_{datetime.now(timezone.utc).strftime('%s')[-6:]}"

        # Build YARA-L rule based on category
        rule_text = ""
        
        if "impersonation" in finding_category.lower() or "service account token" in finding_category.lower():
            rule_text = f'''rule {rule_name} {{
  meta:
    author = "MCP SCC Detection"
    description = "Detects: {finding_category}"
    severity = "{severity}"
    created = "{datetime.now(timezone.utc).isoformat()}"
  events:
    $e.metadata.event_type = "GOOGLE_CLOUD_AUDIT_LOG"
    $e.metadata.log_type = "ADMIN_ACTIVITY"
    $e.target.user.account_type = "SERVICE_ACCOUNT"
    (
      $e.metadata.api_name = "iam.googleapis.com"
      AND (
        $e.metadata.api_method = "SetIamPolicy"
        OR $e.metadata.api_method = "AddBinding"
        OR $e.metadata.api_method = "CreateServiceAccountKey"
      )
    )
  match:
    $e
'''
        
        elif "user-managed key" in finding_category.lower() or "key created" in finding_category.lower():
            rule_text = f'''rule {rule_name} {{
  meta:
    author = "MCP SCC Detection"
    description = "Detects: {finding_category}"
    severity = "{severity}"
    created = "{datetime.now(timezone.utc).isoformat()}"
  events:
    $e.metadata.event_type = "GOOGLE_CLOUD_AUDIT_LOG"
    $e.metadata.log_type = "ADMIN_ACTIVITY"
    $e.metadata.api_name = "iam.googleapis.com"
    $e.metadata.api_method = "CreateServiceAccountKey"
    $e.target.resource_type = "service_account"
  match:
    $e
'''
        
        elif "anomalous grant" in finding_category.lower() or "iam" in finding_category.lower():
            rule_text = f'''rule {rule_name} {{
  meta:
    author = "MCP SCC Detection"
    description = "Detects: {finding_category}"
    severity = "{severity}"
    created = "{datetime.now(timezone.utc).isoformat()}"
  events:
    $e.metadata.event_type = "GOOGLE_CLOUD_AUDIT_LOG"
    $e.metadata.log_type = "ADMIN_ACTIVITY"
    $e.metadata.api_name = "iam.googleapis.com"
    (
      $e.metadata.api_method = "SetIamPolicy"
      OR $e.metadata.api_method = "UpdateIamPolicy"
      OR $e.metadata.api_method = "AddBinding"
    )
  match:
    $e where count($e) >= 1
'''
        
        else:
            # Generic rule for unknown findings
            rule_text = f'''rule {rule_name} {{
  meta:
    author = "MCP SCC Detection"
    description = "Detects: {finding_category}"
    severity = "{severity}"
    created = "{datetime.now(timezone.utc).isoformat()}"
  events:
    $e.metadata.event_type = "GOOGLE_CLOUD_AUDIT_LOG"
    $e.metadata.log_type = "ADMIN_ACTIVITY"
  match:
    $e
'''
        
        # Deploy the rule via SecOps API
        rule_deploy = requests.post(
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}/rules",
            headers=_secops_headers(),
            json={
                "text": rule_text,
                "enabled": True,
            },
            timeout=120,
        )
        
        if rule_deploy.status_code in (200, 201):
            result = rule_deploy.json()
            logger.info(f"Created detection rule: {rule_name}")
            return json.dumps({
                "rule_name": rule_name,
                "status": "created",
                "rule_text": rule_text,
                "api_response": result,
            })
        else:
            logger.warning(f"Rule creation returned {rule_deploy.status_code}")
            return json.dumps({
                "rule_name": rule_name,
                "status": "creation_failed",
                "rule_text": rule_text,
                "error": rule_deploy.text[:500],
                "note": "Rule generated but API deployment failed. Paste the rule_text into SecOps UI manually.",
            })
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🎯 SIMPLE INTENT-BASED TOOLS (Direct NL Matching)
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def get_last_logins(count: int = 5, n: int = 0, N: int = 0, num_events: int = 0, num_logins: int = 0, limit: int = 0, number_of_logins: int = 0) -> str:
    """Get the last N user login events. Use for: 'last 5 logins', 'last 10 logins'."""
    for val in [n, N, num_events, num_logins, limit, number_of_logins]:
        if val > 0:
            count = val
            break
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)
        result = chronicle.search_udm(
            query='metadata.event_type = "USER_LOGIN"',
            start_time=start_time,
            end_time=end_time,
            max_events=count
        )
        events = result.get("events", []) if isinstance(result, dict) else result
        return json.dumps({"count": len(events), "events": events})
    except Exception as e:
        return json.dumps({"error": str(e)})

@app_mcp.tool()
def get_last_cases(count: int = 10, n: int = 0, N: int = 0, num_cases: int = 0, limit: int = 0, number_of_cases: int = 0) -> str:
    """Get the last N SOAR cases. ALWAYS pass count=N when the user specifies a number (e.g. 'last 10 cases' → count=10, 'last 5 cases' → count=5)."""
    for val in [n, N, num_cases, limit, number_of_cases]:
        if val > 0:
            count = val
            break
    try:
        resp = requests.post(
            f"{SIEMPLIFY_BASE}/cases/GetCaseCardsByRequest",
            headers=_siemplify_headers(),
            json={"pageSize": count, "pageNumber": 0},
            timeout=30,
            verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            cases = data.get("caseCards", data if isinstance(data, list) else [])
            return json.dumps({"count": len(cases), "cases": cases})
        return json.dumps({"error": f"Siemplify API [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})

@app_mcp.tool()
def get_last_detections(count: int = 5, n: int = 0, N: int = 0, num_detections: int = 0, limit: int = 0, number_of_detections: int = 0) -> str:
    """Get the last N detection alerts. Use for: 'last 5 detections', 'last 10 detections'."""
    for val in [n, N, num_detections, limit, number_of_detections]:
        if val > 0:
            count = val
            break
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # list_detections requires rule_id; use search_rule_alerts instead for "all" detections
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(hours=24)
        result = chronicle.search_rule_alerts(
            start_time=start_dt,
            end_time=end_dt,
            page_size=count
        )
        detections = result.get('alerts', result.get('detections', [])) if isinstance(result, dict) else result
        return json.dumps({"count": len(detections), "detections": detections})
    except Exception as e:
        return json.dumps({"error": str(e)})
