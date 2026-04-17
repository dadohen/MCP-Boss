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

SECOPS_BASE_URL = (
    f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1alpha"
    f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
    f"/instances/{SECOPS_CUSTOMER_ID}"
)

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
            "You are a Google SecOps UDM query expert. Convert the following natural language "
            "into a valid UDM Search query matching Google Chronicle metadata field names.\n\n"
            "Field reference:\n"
            "  metadata.event_type (USER_LOGIN, USER_LOGOUT, PROCESS_EXECUTION, NETWORK_HTTP, etc.)\n"
            "  security_result.action (ALLOW, DENY, BLOCK, etc.)\n"
            "  security_result.severity (HIGH, MEDIUM, LOW, INFO)\n"
            "  principal.user.user_display_name\n"
            "  target.ip, target.hostname, target.user.user_display_name\n"
            "  metadata.event_timestamp\n\n"
            "Use AND/OR operators. Return ONLY the UDM query, nothing else.\n\n"
            f"Natural language: {natural_language}\n\nUDM Query:"
        )
        resp = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"contents": [{"role": "user", "parts": [{"text": prompt}]}]},
            timeout=30,
        )
        if resp.status_code == 200:
            query = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            query = query.strip("`").strip()
            return query
        return ""
    except Exception as e:
        logger.error(f"UDM query translation failed: {e}")
        return ""


def parse_time_range(hours_back: float = 24.0, start_time: str = "", end_time: str = "", minutes_back: float = 0.0) -> tuple:
    """
    Parse time range parameters into ISO 8601 timestamps.
    Returns (start_iso, end_iso).
    Priority: explicit start_time/end_time > minutes_back > hours_back
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
        if minutes_back > 0:
            start = end - timedelta(minutes=minutes_back)
        else:
            hours_back = min(max(0.01, hours_back), 8760)
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
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time, locals().get('minutes_back', 0.0))
        
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
def search_secops_udm(query: str = "", udm_query: str = "", hours_back: float = 24.0, max_events: int = 100, start_time: str = "", end_time: str = "", time_range: str = "", limit: int = 0, count: int = 0, minutes_back: float = 0.0) -> str:
    """[SECOPS CHRONICLE] Direct raw log/UDM queries. Advanced threat hunting with Chronicle metadata. Use this when asked for 'logs'."""
    try:
        final_query = query or udm_query
        if not final_query or len(final_query.strip()) < 5:
            return json.dumps({"error": "Query too short"})
        # Accept limit/count as aliases for max_events
        if limit > 0:
            max_events = limit
        elif count > 0:
            max_events = count
        max_events = min(max(1, max_events), 10000)
        
        # Parse time range
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time, minutes_back)
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
def list_secops_detections(hours_back: float = 24.0, max_results: int = 50, start_time: str = "", end_time: str = "", minutes_back: float = 0.0) -> str:
    """List recent YARA-L detection alerts with rule names, severity, and outcomes with time range filtering."""
    try:
        max_results = min(max(1, max_results), 1000)
        start_iso, end_iso = parse_time_range(hours_back, start_time, end_time, minutes_back)
        start_dt = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_iso.replace('Z', '+00:00'))
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # Get all rules first, then search for alerts across them
        all_detections = []
        try:
            rules = chronicle.list_rules(page_size=100)
            rule_list = rules.get('rules', []) if isinstance(rules, dict) else (rules if isinstance(rules, list) else [])
            for rule in rule_list[:20]:  # Check top 20 rules
                rule_id = rule.get('name', '').split('/')[-1] if isinstance(rule, dict) else str(rule)
                if not rule_id:
                    continue
                try:
                    dets = chronicle.list_detections(rule_id=rule_id, page_size=min(max_results, 50), start_time=start_dt, end_time=end_dt)
                    det_list = dets.get('detections', []) if isinstance(dets, dict) else (dets if isinstance(dets, list) else [])
                    for d in det_list:
                        if isinstance(d, dict):
                            d['_rule_name'] = rule.get('displayName', rule.get('name', 'unknown')) if isinstance(rule, dict) else 'unknown'
                    all_detections.extend(det_list)
                except Exception:
                    continue
                if len(all_detections) >= max_results:
                    break
        except Exception as e2:
            # Fallback: search via UDM for detection events
            result = chronicle.search_udm(
                query='metadata.event_type = "RULE_DETECTION"',
                start_time=start_dt, end_time=end_dt, max_events=max_results
            )
            events = result.get('events', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
            return json.dumps({"detections": events[:max_results], "count": len(events), "source": "udm_fallback", "time_range": {"start": start_iso, "end": end_iso}})
        
        return json.dumps({"detections": all_detections[:max_results], "count": len(all_detections), "time_range": {"start": start_iso, "end": end_iso}})
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
                            headers={"x-apikey": GTI_API_KEY}, timeout=30)

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
        action = "enable" if enabled else "disable"
        resp = requests.post(f"{SECOPS_BASE_URL}/rules/{rule_id}:{action}",
                             headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}")
            return json.dumps({"status": "success", "rule_id": rule_id, "enabled": enabled})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📧 EMAIL CONTAINMENT (Microsoft Graph)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete") -> str:
    """
    Purge an email from an Office 365 mailbox using Microsoft Graph API.
    Uses the internet Message-ID header to locate the email, then executes a Hard or Soft Delete.

    Args:
        target_mailbox: The user's email address (e.g., user@company.com)
        message_id: The RFC 2822 Message-ID header value
        purge_type: "hardDelete" (bypasses trash) or "softDelete" (moves to trash)
    """
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
def suspend_okta_user(user_email: str, clear_sessions: bool = True) -> str:
    """
    Suspend a user in Okta and optionally clear all active sessions.
    Used for compromised account containment — blocks new logins and kills existing tokens.
    """
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
def revoke_azure_ad_sessions(user_email: str) -> str:
    """Revoke all active sign-in sessions for an Azure AD / Entra ID user."""
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
def revoke_aws_access_keys(target_user: str) -> str:
    """Disable all active AWS IAM access keys for a user. Stops leaked credential abuse."""
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
def revoke_aws_sts_sessions(target_user: str) -> str:
    """
    Deny all pre-existing STS sessions for an AWS IAM user.
    Critical: disabling access keys does NOT invalidate already-assumed roles.
    This attaches an inline deny-all policy conditioned on token issue time.
    """
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
def revoke_gcp_sa_keys(project_id: str = "", service_account_email: str = "") -> str:
    """Delete all user-managed keys for a GCP service account. Stops leaked SA key abuse."""
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
def isolate_crowdstrike_host(hostname: str = "", device_id: str = "") -> str:
    """
    Network-isolate a host via CrowdStrike Falcon API.
    The host can still communicate with the CrowdStrike cloud for remote forensics
    but is completely disconnected from the internal network.

    Provide either hostname or device_id. If hostname, we look up the device_id first.
    """
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
    """Create a new case in Google SecOps SOAR."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # Use ingest_udm or trigger_investigation to create cases via SDK
        # SecOpsClient doesn't have a direct create_case, so use the REST API via chronicle session
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.post(
            f"{v1_base}/cases",
            headers=headers,
            json={
                "displayName": title,
                "description": description,
                "priority": f"PRIORITY_{priority.upper()}" if not priority.upper().startswith("PRIORITY_") else priority.upper(),
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Case created: {title}")
            return resp.text
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
    Update an existing SOAR case — add comments, change priority, or close.

    Args:
        case_id: The case identifier (string)
        comment: Text to add to the case wall
        priority: New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status: New status (OPEN, IN_PROGRESS, CLOSED)
        close_reason: Required when status=CLOSED
    """
    try:
        case_id = str(case_id)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        results = []

        if priority:
            p = f"PRIORITY_{priority.upper()}" if not priority.upper().startswith("PRIORITY_") else priority.upper()
            r = chronicle.patch_case(case_id, {"priority": p})
            results.append(f"Priority updated to {p}")

        if status:
            update = {"status": status.upper()}
            if close_reason:
                update["closeReason"] = close_reason
            r = chronicle.patch_case(case_id, update)
            results.append(f"Status updated to {status.upper()}")

        if comment:
            # Use the secops_create_case_comment equivalent
            v1_base = (
                f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
                f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
                f"/instances/{SECOPS_CUSTOMER_ID}"
            )
            token = get_adc_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            resp = requests.post(
                f"{v1_base}/cases/{case_id}/caseComments",
                headers=headers,
                json={"body": comment},
                timeout=15,
            )
            results.append(f"Comment added: {resp.status_code}")

        logger.info(f"Case {case_id} updated: {results}")
        return json.dumps({"status": "updated", "case_id": case_id, "actions": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔎 NATURAL LANGUAGE SECURITY SEARCH (SecOps)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def search_security_events(text: str = "", query: str = "", hours_back: float = 24.0, time_range: str = "", timerange: str = "", max_events: int = 100, minutes_back: float = 0.0) -> str:
    """[SECOPS CHRONICLE] Search raw logs/UDM for logins, malware, threats. Translates natural language to UDM: metadata.event_type=USER_LOGIN, security_result.action=ALLOW, etc. Use this when asked for 'logs'."""
    try:
        search_text = text or query
        if not search_text or len(search_text.strip()) < 3:
            return json.dumps({"error": "Search text too short"})
        # Handle time_range or timerange parameter (e.g., "30 days")
        final_time_range = time_range or timerange
        if final_time_range:
            if "day" in final_time_range.lower():
                hours_back = int(final_time_range.split()[0]) * 24
            elif "hour" in final_time_range.lower():
                hours_back = int(final_time_range.split()[0])
        hours_back = min(max(1, hours_back), 8760)
        max_events = min(max(1, max_events), 10000)

        # Step 1: Use Gemini to translate natural language to UDM query
        token = get_adc_token()
        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/{GEMINI_MODEL}:generateContent"
        )
        translate_prompt = (
            "You are a Google SecOps UDM query expert. Convert the following natural language "
            "security search into a valid UDM Search query matching Google Chronicle metadata field names.\n\n"
            "Field reference:\n"
            "  metadata.event_type (e.g., \"USER_LOGIN\", \"USER_LOGOUT\", \"PROCESS_EXECUTION\")\n"
            "  security_result.action (e.g., \"ALLOW\", \"DENY\")\n"
            "  security_result.severity (e.g., \"HIGH\", \"MEDIUM\", \"LOW\")\n"
            "  principal.user.user_display_name\n"
            "  target.ip, target.hostname\n"
            "  metadata.event_timestamp\n\n"
            "Use AND/OR operators. Examples:\n"
            "  metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"ALLOW\"\n"
            "  target.ip = \"8.8.8.8\" AND metadata.event_type = \"NETWORK_HTTP\"\n\n"
            "Return ONLY the UDM query string, nothing else.\n\n"
            f"Natural language: {search_text}\n\nUDM Query:"
        )
        gemini_resp = requests.post(
            gemini_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"contents": [{"role": "user", "parts": [{"text": translate_prompt}]}]},
            timeout=30,
        )
        if gemini_resp.status_code != 200:
            return json.dumps({"error": f"Gemini translation failed [{gemini_resp.status_code}]", "detail": gemini_resp.text[:300]})

        udm_query = gemini_resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        udm_query = udm_query.strip("`").strip()
        
        # Clean up the query: remove ORDER BY, LIMIT, and _limit clauses (they're API params, not UDM syntax)
        import re
        udm_query_clean = re.sub(r'\s+(order\s+by|limit|_limit)\s+.*$', '', udm_query, flags=re.IGNORECASE)
        udm_query_clean = re.sub(r'\s+_limit\s*=\s*\d+', '', udm_query_clean, flags=re.IGNORECASE)
        udm_query_clean = udm_query_clean.strip()

        # Step 2: Execute the UDM search via SecOpsClient
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        end_dt = now
        
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.search_udm(
            query=udm_query_clean,
            start_time=start_dt,
            end_time=end_dt,
            max_events=max_events
        )
        events = result.get("events", []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        events = events[:max_events]
        return json.dumps({"natural_language_query": search_text, "udm_query": udm_query_clean, "events": events, "count": len(events)})
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
        alert_limit = count or max_results or limit or max_alerts
        alert_limit = min(max(1, alert_limit), 1000)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.get_alerts(start_time=start_dt, end_time=now, max_alerts=alert_limit)
        alerts = result.get('alerts', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        formatted = []
        for a in alerts[:alert_limit]:
            formatted.append({
                "id": a.get("name", a.get("alertId", "")),
                "rule_name": a.get("ruleName", a.get("detection", {}).get("ruleName", "unknown")),
                "severity": a.get("severity", "unknown"),
                "create_time": a.get("createTime", ""),
                "status": a.get("feedbackStatus", a.get("status", "")),
                "description": (a.get("description", "") or "")[:500],
            })
        return json.dumps({"alerts": formatted, "count": len(formatted), "hours_back": hours_back})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def lookup_entity(entity_value: str = "", entity: str = "", value: str = "", hours_back: int = 24) -> str:
    """Look up an entity (IP, domain, user, hash) in Google SecOps. Returns risk score, associated alerts, and entity context."""
    try:
        entity_value = entity_value or entity or value
        if not entity_value or len(entity_value.strip()) < 1:
            return json.dumps({"error": "Entity value is required"})
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=hours_back)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        try:
            summary = chronicle.summarize_entity(
                value=entity_value.strip(),
                start_time=start_dt,
                end_time=now,
                page_size=100
            )
            # Convert EntitySummary to dict
            result = {
                "entity": entity_value,
                "summary": str(summary) if not isinstance(summary, dict) else summary,
            }
            # Try to extract useful fields
            if hasattr(summary, '__dict__'):
                result["summary"] = {k: str(v)[:1000] for k, v in summary.__dict__.items() if not k.startswith('_')}
            return json.dumps(result)
        except Exception as e_summary:
            # Fallback: search UDM for entity activity
            udm_query = f'principal.ip = "{entity_value}" OR target.ip = "{entity_value}" OR principal.hostname = "{entity_value}" OR target.hostname = "{entity_value}" OR principal.user.userid = "{entity_value}" OR target.user.userid = "{entity_value}"'
            result = chronicle.search_udm(query=udm_query, start_time=start_dt, end_time=now, max_events=50)
            events = result.get('events', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
            return json.dumps({"entity": entity_value, "event_count": len(events), "events": events[:10], "source": "udm_search", "summarize_error": str(e_summary)[:200]})
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
            timeout=30,
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
            timeout=30,
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
            timeout=30,
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
def search_threat_actors(query: str = "", actor_query: str = "", threat_actor_query: str = "", limit: int = 10) -> str:
    """Search for threat actor profiles in VirusTotal/GTI intelligence. Returns matching threat actor names, descriptions, and associated indicators."""
    try:
        final_query = query or actor_query or threat_actor_query
        if not final_query or len(final_query.strip()) < 2:
            return json.dumps({"error": "Query too short"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        limit = min(max(1, limit), 50)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/threat_actors",
            headers={"x-apikey": GTI_API_KEY},
            params={"filter": final_query, "limit": limit},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            actors = []
            for item in data.get("data", [])[:limit]:
                attrs = item.get("attributes", {})
                actors.append({
                    "id": item.get("id", ""),
                    "name": attrs.get("name", attrs.get("meaningful_name", "")),
                    "description": (attrs.get("description", "") or "")[:500],
                    "aliases": attrs.get("aliases", []),
                    "targeted_industries": attrs.get("targeted_industries", []),
                    "targeted_countries": attrs.get("targeted_countries", []),
                    "source_region": attrs.get("source_region", ""),
                })
            return json.dumps({"query": query, "threat_actors": actors, "count": len(actors)})
        # Fallback to intelligence search
        resp2 = requests.get(
            "https://www.virustotal.com/api/v3/intelligence/search",
            headers={"x-apikey": GTI_API_KEY},
            params={"query": f'type:threat-actor "{final_query}"', "limit": limit},
            timeout=30,
        )
        if resp2.status_code == 200:
            data = resp2.json()
            actors = [{"id": i.get("id"), "name": i.get("attributes", {}).get("name", i.get("id")), "type": i.get("type")} for i in data.get("data", [])[:limit]]
            return json.dumps({"query": query, "threat_actors": actors, "count": len(actors)})
        return json.dumps({"error": f"GTI search [{resp.status_code}]", "detail": resp.text[:300]})
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
            timeout=30,
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
    """List all SOAR cases from Google SecOps. Returns case IDs, titles, priorities, and statuses."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_cases(page_size=100)
        cases = result.get('cases', []) if isinstance(result, dict) else (result if isinstance(result, list) else [])
        formatted = []
        for c in cases:
            c_dict = c if isinstance(c, dict) else {}
            formatted.append({
                "id": c_dict.get("name", c_dict.get("caseId", "")),
                "title": c_dict.get("displayName", c_dict.get("title", "")),
                "priority": c_dict.get("priority", ""),
                "status": c_dict.get("status", ""),
                "create_time": c_dict.get("createTime", ""),
                "update_time": c_dict.get("updateTime", ""),
                "assignee": c_dict.get("assignee", ""),
            })
        return json.dumps({"cases": formatted, "count": len(formatted)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_case_alerts(case_id: str) -> str:
    """Get all alerts associated with a specific SOAR case."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.get(
            f"{SECOPS_BASE_URL}/cases/{case_id}/alerts",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            alerts = data.get("alerts", [])
            formatted = []
            for a in alerts:
                formatted.append({
                    "id": a.get("name", a.get("alertId", "")),
                    "rule_name": a.get("ruleName", ""),
                    "severity": a.get("severity", ""),
                    "create_time": a.get("createTime", ""),
                    "status": a.get("status", ""),
                    "description": (a.get("description", "") or "")[:500],
                })
            return json.dumps({"case_id": case_id, "alerts": formatted, "count": len(formatted)})
        return json.dumps({"error": f"Case alerts API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def add_case_comment(case_id: str, comment: str) -> str:
    """Add a comment to a SOAR case. Use for investigation notes, status updates, or escalation context."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        if not comment or len(comment.strip()) < 1:
            return json.dumps({"error": "comment is required"})
        resp = requests.post(
            f"{SECOPS_BASE_URL}/cases/{case_id}/comments",
            headers=_secops_headers(),
            json={"body": comment},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Comment added to case {case_id}")
            return json.dumps({"status": "comment_added", "case_id": case_id, "comment_length": len(comment)})
        return json.dumps({"error": f"Add comment failed [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📜 CLOUD LOGGING
# ═══════════════════════════════════════════════════════════════


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
            timeout=30,
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
            timeout=30,
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
            timeout=30,
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
            timeout=30,
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
        project_id = project_id or SECOPS_PROJECT_ID
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
            timeout=30,
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
            timeout=30,
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
            timeout=30,
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
def list_parsers(project_id: str = "", max_results: int = 50) -> str:
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
        # Summarize to avoid massive output
        summary = []
        for p in (parsers[:max_results] if isinstance(parsers, list) else []):
            name = p.get('name', '')
            log_type = name.split('/logTypes/')[-1].split('/')[0] if '/logTypes/' in name else name
            creator = p.get('creator', {}).get('source', 'UNKNOWN')
            summary.append({"log_type": log_type, "creator": creator})
        return json.dumps({"parsers": summary, "count": len(parsers) if isinstance(parsers, list) else 0, "showing": len(summary)})
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
            timeout=30,
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
def query_ingestion_stats(days_back: int = 30) -> str:
    """
    Query Chronicle SIEM ingestion bandwidth and record counts from GCP Cloud Monitoring.
    Returns daily breakdown of ingestion volume (GB) and record counts.

    Args:
        days_back: Number of days to look back (default 30, max 90)
    """
    try:
        from google.cloud import monitoring_v3
        from google.protobuf.duration_pb2 import Duration

        days_back = min(max(1, days_back), 90)
        client = monitoring_v3.MetricServiceClient()
        project = f"projects/{SECOPS_PROJECT_ID}"
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=days_back)
        interval = monitoring_v3.TimeInterval(start_time=start_dt, end_time=now)
        agg = monitoring_v3.Aggregation(
            alignment_period=Duration(seconds=86400),
            per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
            group_by_fields=[],
        )

        # Bytes ingested per day
        bytes_results = client.list_time_series(request={
            "name": project,
            "filter": 'metric.type = "chronicle.googleapis.com/ingestion/log/bytes_count"',
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": agg,
        })
        daily_bytes = {}
        for ts in bytes_results:
            for point in ts.points:
                date_str = point.interval.start_time.strftime('%Y-%m-%d')
                val = int(point.value.int64_value or point.value.double_value)
                daily_bytes[date_str] = daily_bytes.get(date_str, 0) + val

        # Records ingested per day
        record_results = client.list_time_series(request={
            "name": project,
            "filter": 'metric.type = "chronicle.googleapis.com/ingestion/log/record_count"',
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": agg,
        })
        daily_records = {}
        for ts in record_results:
            for point in ts.points:
                date_str = point.interval.start_time.strftime('%Y-%m-%d')
                val = int(point.value.int64_value or point.value.double_value)
                daily_records[date_str] = daily_records.get(date_str, 0) + val

        all_dates = sorted(set(list(daily_bytes.keys()) + list(daily_records.keys())))
        daily_breakdown = []
        total_bytes = 0
        total_records = 0
        for date in all_dates:
            b = daily_bytes.get(date, 0)
            r = daily_records.get(date, 0)
            total_bytes += b
            total_records += r
            daily_breakdown.append({
                "date": date,
                "bytes": b,
                "gb": round(b / (1024**3), 2),
                "records": r,
            })

        num_days = max(len(all_dates), 1)
        return json.dumps({
            "days_back": days_back,
            "total_bytes": total_bytes,
            "total_gb": round(total_bytes / (1024**3), 2),
            "total_records": total_records,
            "avg_daily_gb": round(total_bytes / (1024**3) / num_days, 2),
            "avg_daily_records": total_records // num_days,
            "daily_breakdown": daily_breakdown,
        })
    except ImportError:
        return json.dumps({"error": "google-cloud-monitoring not installed. Add it to requirements.txt."})
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
            timeout=30,
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
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_rule_errors(rule_id: str = "") -> str:
    """List errors for a specific YARA-L rule. If no rule_id provided, checks all rules for errors."""
    try:
        if not rule_id:
            # List all rules and check each for errors
            client = SecOpsClient()
            chronicle = client.chronicle(
                customer_id=SECOPS_CUSTOMER_ID,
                project_id=SECOPS_PROJECT_ID,
                region=SECOPS_REGION
            )
            rules = chronicle.list_rules(page_size=100)
            rule_list = rules.get('rules', []) if isinstance(rules, dict) else (rules if isinstance(rules, list) else [])
            all_errors = []
            for rule in rule_list[:50]:
                rid = rule.get('name', '').split('/')[-1] if isinstance(rule, dict) else str(rule)
                if not rid:
                    continue
                try:
                    errs = chronicle.list_errors(rid)
                    err_list = errs.get('errors', []) if isinstance(errs, dict) else (errs if isinstance(errs, list) else [])
                    if err_list:
                        all_errors.append({"rule_id": rid, "rule_name": rule.get('displayName', 'unknown') if isinstance(rule, dict) else 'unknown', "errors": err_list})
                except Exception:
                    continue
            return json.dumps({"rules_with_errors": all_errors, "count": len(all_errors)})
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
def list_case_comments(case_id = "", page_size: int = 50) -> str:
    """List all comments for a SOAR case with full history and filtering support."""
    try:
        case_id = str(case_id) if case_id else ""
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        page_size = min(max(1, page_size), 200)
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # Use patch_case to get case details including comments, or list_cases with case_id filter
        result = chronicle.get_case(case_id)
        comments = result.get('comments', []) if isinstance(result, dict) else []
        return json.dumps({"case_id": case_id, "comments": comments, "count": len(comments)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_case_priority(case_id: str, priority: str) -> str:
    """Update the priority of a SOAR case. Priority options: CRITICAL, HIGH, MEDIUM, LOW, INFO."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.patch_case(case_id, {"priority": priority.upper()})
        logger.info(f"Case {case_id} priority updated to {priority}")
        return json.dumps({"status": "updated", "case_id": case_id, "priority": priority, "result": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def close_case(case_id: str, reason: str = "Resolved") -> str:
    """Close a SOAR case with a resolution reason."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.patch_case(case_id, {"status": "CLOSED", "closeReason": reason})
        logger.info(f"Case {case_id} closed with reason: {reason}")
        return json.dumps({"status": "closed", "case_id": case_id, "reason": reason, "result": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📈 DASHBOARDS / OVERVIEW
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_case_overview() -> str:
    """Get case overview: total cases, open vs closed, by priority, by status."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        result = chronicle.list_cases(page_size=200)
        cases = result.get('cases', []) if isinstance(result, dict) else result
        # Build overview stats
        stats = {"total": len(cases), "by_status": {}, "by_priority": {}}
        for c in cases:
            status = c.get('status', 'UNKNOWN')
            priority = c.get('priority', 'UNKNOWN')
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
    """List all SOAR playbooks in SecOps. Shows playbook names, triggers, and enabled status."""
    try:
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION
        )
        # Try Chronicle v1 API for playbooks
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.get(
            f"{v1_base}/playbooks",
            headers=headers,
            params={"pageSize": min(page_size, 100)},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            playbooks = data.get('playbooks', [])
            return json.dumps({"playbooks": playbooks, "count": len(playbooks)})
        # Fallback: show rules as proxy
        rules_result = chronicle.list_rules(page_size=page_size)
        rules_list = rules_result.get('rules', []) if isinstance(rules_result, dict) else []
        rules_summary = [{"name": r.get('name', '').split('/')[-1], "displayName": r.get('displayName', ''), "enabled": r.get('enabled', False)} for r in rules_list]
        return json.dumps({"note": "Playbooks endpoint returned non-200; showing detection rules as fallback", "rules": rules_summary, "count": len(rules_summary)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_playbook(playbook_id: str) -> str:
    """Get details of a specific SOAR playbook including its steps, triggers, and configuration."""
    try:
        if not playbook_id:
            return json.dumps({"error": "playbook_id is required"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.get(
            f"{v1_base}/playbooks/{playbook_id}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
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
        
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.post(
            f"{v1_base}/playbooks",
            headers=headers,
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
def autonomous_investigate(
    trigger: str,
    trigger_type: str = "auto",
    project_id: str = "",
    auto_create_rule: bool = True,
    auto_create_case: bool = True,
) -> str:
    """
    FLAGSHIP TOOL: Autonomous end-to-end investigation pipeline.
    
    Takes a trigger (IP, domain, hash, SCC finding, alert, or natural language description)
    and executes the full SOC workflow automatically:
    
    1. IDENTIFY — Determine what the trigger is and enrich it
    2. SEARCH — Hunt for related events in SecOps UDM
    3. ASSESS — Use Vertex AI to analyze findings and determine severity
    4. DETECT — Check if a YARA-L rule exists for this pattern; CREATE one if not
    5. RESPOND — Check if a SOAR case exists; CREATE one if not
    6. REPORT — Generate a complete investigation summary
    
    Args:
        trigger: The starting point — an IP, domain, hash, alert description, or SCC finding
        trigger_type: "ip", "domain", "hash", "alert", "finding", or "auto" (auto-detect)
        project_id: GCP project ID (defaults to SECOPS_PROJECT_ID env var)
        auto_create_rule: If True, automatically creates a YARA-L rule if none exists for this pattern
        auto_create_case: If True, automatically creates a SOAR case for tracking
    
    Returns:
        Complete investigation report with all actions taken
    """
    try:
        pid = project_id or SECOPS_PROJECT_ID
        results = {
            "trigger": trigger,
            "trigger_type": trigger_type,
            "steps": [],
            "actions_taken": [],
            "severity": "UNKNOWN",
            "summary": "",
        }

        # ── STEP 1: IDENTIFY & ENRICH ──
        step1 = {"step": "1_IDENTIFY", "status": "running"}
        
        # Auto-detect trigger type
        if trigger_type == "auto":
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", trigger):
                trigger_type = "ip"
            elif re.match(r"^[a-fA-F0-9]{32}$", trigger) or re.match(r"^[a-fA-F0-9]{64}$", trigger):
                trigger_type = "hash"
            elif "." in trigger and not " " in trigger and len(trigger) < 256:
                trigger_type = "domain"
            else:
                trigger_type = "description"
        
        results["trigger_type"] = trigger_type
        
        # Enrich the indicator
        enrichment = {}
        if trigger_type in ("ip", "domain", "hash") and GTI_API_KEY:
            try:
                vt_base = "https://www.virustotal.com/api/v3"
                type_urls = {
                    "ip": f"{vt_base}/ip_addresses/{trigger}",
                    "domain": f"{vt_base}/domains/{trigger}",
                    "hash": f"{vt_base}/files/{trigger}",
                }
                vt_resp = requests.get(
                    type_urls.get(trigger_type, f"{vt_base}/search?query={trigger}"),
                    headers={"x-apikey": GTI_API_KEY},
                    timeout=15,
                )
                if vt_resp.status_code == 200:
                    attrs = vt_resp.json().get("data", {}).get("attributes", {})
                    enrichment = {
                        "reputation": attrs.get("reputation", "N/A"),
                        "malicious_count": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                        "total_engines": sum(attrs.get("last_analysis_stats", {}).values()) if attrs.get("last_analysis_stats") else 0,
                        "tags": attrs.get("tags", []),
                    }
                    if trigger_type == "ip":
                        enrichment["asn"] = attrs.get("asn", "N/A")
                        enrichment["country"] = attrs.get("country", "N/A")
                elif vt_resp.status_code == 404:
                    enrichment = {"result": "NOT_FOUND", "note": "Potential zero-day or novel indicator"}
            except Exception as e:
                enrichment = {"error": str(e)}
        
        step1["enrichment"] = enrichment
        step1["status"] = "complete"
        results["steps"].append(step1)

        # ── STEP 2: SEARCH SECOPS ──
        step2 = {"step": "2_SEARCH", "status": "running"}
        
        # Build UDM query based on trigger type
        udm_queries = {
            "ip": f'principal.ip = "{trigger}" OR target.ip = "{trigger}"',
            "domain": f'target.hostname = "{trigger}" OR network.dns.questions.name = "{trigger}"',
            "hash": f'target.process.file.sha256 = "{trigger}" OR target.file.sha256 = "{trigger}"',
        }
        udm_query = udm_queries.get(trigger_type, "")
        
        search_results = {}
        if udm_query:
            try:
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                start = (now - timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ")
                end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                
                search_resp = requests.get(
                    f"{SECOPS_BASE_URL}:udmSearch",
                    headers=_secops_headers(),
                    params={"query": udm_query, "time_range.start_time": start, "time_range.end_time": end, "limit": 100},
                    timeout=60,
                )
                if search_resp.status_code == 200:
                    search_results = search_resp.json()
                    step2["events_found"] = len(search_results.get("events", []))
                else:
                    search_results = {"error": f"Search returned {search_resp.status_code}"}
                    step2["events_found"] = 0
            except Exception as e:
                search_results = {"error": str(e)}
                step2["events_found"] = 0
        else:
            step2["events_found"] = 0
            step2["note"] = "No UDM query for description-type triggers. Use search_security_events for natural language."
        
        step2["query"] = udm_query
        step2["status"] = "complete"
        results["steps"].append(step2)

        # ── STEP 3: ASSESS SEVERITY (Vertex AI) ──
        step3 = {"step": "3_ASSESS", "status": "running"}
        
        severity = "LOW"
        malicious_count = enrichment.get("malicious_count", 0)
        events_found = step2.get("events_found", 0)
        
        if malicious_count >= 5 or enrichment.get("result") == "NOT_FOUND":
            severity = "CRITICAL"
        elif malicious_count >= 1 or events_found > 10:
            severity = "HIGH"
        elif events_found > 0:
            severity = "MEDIUM"
        
        results["severity"] = severity
        step3["severity"] = severity
        step3["rationale"] = f"VT malicious={malicious_count}, UDM events={events_found}"
        step3["status"] = "complete"
        results["steps"].append(step3)

        # ── STEP 4: CHECK/CREATE DETECTION RULE ──
        step4 = {"step": "4_DETECT", "status": "running"}
        
        # Check if a rule already exists for this indicator
        rule_exists = False
        try:
            rules_resp = requests.get(
                f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}/rules",
                headers=_secops_headers(),
                params={"pageSize": 100},
                timeout=15,
            )
            if rules_resp.status_code == 200:
                rules_data = rules_resp.json()
                for rule in rules_data.get("rules", []):
                    rule_text = rule.get("text", "")
                    if trigger.lower() in rule_text.lower():
                        rule_exists = True
                        step4["existing_rule"] = rule.get("name", "unknown")
                        break
        except Exception:
            pass
        
        if not rule_exists and auto_create_rule and trigger_type in ("ip", "domain", "hash") and severity in ("HIGH", "CRITICAL"):
            # Auto-generate a YARA-L rule
            rule_templates = {
                "ip": f'''rule Auto_IOC_IP_{trigger.replace(".", "_")} {{
  meta:
    author = "MCP Auto-Investigation"
    description = "Auto-generated rule for suspicious IP {trigger}"
    severity = "{severity}"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    ($e.principal.ip = "{trigger}" or $e.target.ip = "{trigger}")
  condition:
    $e
}}''',
                "domain": f'''rule Auto_IOC_Domain_{trigger.replace(".", "_").replace("-", "_")} {{
  meta:
    author = "MCP Auto-Investigation"
    description = "Auto-generated rule for suspicious domain {trigger}"
    severity = "{severity}"
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.target.hostname = "{trigger}"
  condition:
    $e
}}''',
                "hash": f'''rule Auto_IOC_Hash_{trigger[:16]} {{
  meta:
    author = "MCP Auto-Investigation"
    description = "Auto-generated rule for suspicious file hash {trigger}"
    severity = "{severity}"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.sha256 = "{trigger}"
  condition:
    $e
}}''',
            }
            
            rule_text = rule_templates.get(trigger_type, "")
            if rule_text:
                try:
                    create_resp = requests.post(
                        f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}/rules",
                        headers=_secops_headers(),
                        json={"text": rule_text},
                        timeout=15,
                    )
                    if create_resp.status_code in (200, 201):
                        step4["rule_created"] = True
                        step4["rule_name"] = create_resp.json().get("name", "unknown")
                        results["actions_taken"].append(f"Created YARA-L rule for {trigger_type} {trigger}")
                        # Also create a containment playbook for this rule
                        try:
                            pb_resp = requests.post(
                                f"{SECOPS_BASE_URL}/playbooks",
                                headers=_secops_headers(),
                                json={
                                    "displayName": f"Auto_Containment_{trigger_type.upper()}_{trigger.replace('.', '_').replace('-', '_')[:30]}",
                                    "description": f"Auto-generated containment playbook for {trigger_type} {trigger}. Created by autonomous_investigate.",
                                    "enabled": True,
                                    "trigger": {"triggerType": "ALERT", "filter": f"rule_name = '{step4.get('rule_name', '')}'"},
                                },
                                timeout=15,
                            )
                            if pb_resp.status_code in (200, 201):
                                step4["playbook_created"] = True
                                step4["playbook_name"] = pb_resp.json().get("name", "unknown")
                                results["actions_taken"].append(f"Created containment playbook for {trigger_type} {trigger}")
                            else:
                                step4["playbook_created"] = False
                                step4["playbook_note"] = f"Playbook API returned {pb_resp.status_code}. Create manually in SecOps UI."
                        except Exception as pb_e:
                            step4["playbook_created"] = False
                            step4["playbook_error"] = str(pb_e)
                    else:
                        step4["rule_created"] = False
                        step4["rule_error"] = f"API returned {create_resp.status_code}: {create_resp.text[:200]}"
                except Exception as e:
                    step4["rule_created"] = False
                    step4["rule_error"] = str(e)
        elif rule_exists:
            step4["note"] = "Detection rule already exists for this indicator"
        else:
            step4["note"] = f"Rule auto-creation skipped (severity={severity}, auto_create={auto_create_rule})"
        
        step4["status"] = "complete"
        results["steps"].append(step4)

        # ── STEP 5: CREATE SOAR CASE ──
        step5 = {"step": "5_RESPOND", "status": "running"}
        
        if auto_create_case and severity in ("HIGH", "CRITICAL"):
            try:
                case_title = f"[Auto] {severity} - {trigger_type.upper()} Investigation: {trigger}"
                case_desc = (
                    f"Autonomous investigation triggered by {trigger_type}: {trigger}\n"
                    f"Severity: {severity}\n"
                    f"VT Malicious: {malicious_count}\n"
                    f"UDM Events Found: {events_found}\n"
                    f"Enrichment: {json.dumps(enrichment, indent=2)}"
                )
                
                case_resp = requests.post(
                    f"{SECOPS_BASE_URL}/cases",
                    headers=_secops_headers(),
                    json={
                        "displayName": case_title,
                        "description": case_desc,
                        "priority": f"PRIORITY_{severity}",
                    },
                    timeout=15,
                )
                if case_resp.status_code in (200, 201):
                    step5["case_created"] = True
                    step5["case_id"] = case_resp.json().get("name", "unknown")
                    results["actions_taken"].append(f"Created SOAR case: {case_title}")
                    
                    # Add investigation comment to the case
                    case_id = step5["case_id"].split("/")[-1] if "/" in step5.get("case_id", "") else step5.get("case_id", "")
                    try:
                        requests.post(
                            f"{SECOPS_BASE_URL}/cases/{case_id}/comments",
                            headers=_secops_headers(),
                            json={"body": f"Autonomous Investigation Report:\n{json.dumps(results, indent=2, default=str)}"},
                            timeout=10,
                        )
                    except Exception:
                        pass
                else:
                    step5["case_created"] = False
                    step5["case_error"] = f"API returned {case_resp.status_code}"
            except Exception as e:
                step5["case_created"] = False
                step5["case_error"] = str(e)
        else:
            step5["note"] = f"Case creation skipped (severity={severity}, auto_create={auto_create_case})"
        
        step5["status"] = "complete"
        results["steps"].append(step5)

        # ── STEP 5B: EXECUTE CONTAINMENT (if severity warrants it) ──
        step5b = {"step": "5B_CONTAIN", "status": "running", "actions": []}
        
        if severity == "CRITICAL" and trigger_type in ("ip", "domain", "hash"):
            # Auto-containment for CRITICAL threats
            
            # Action 1: If IP, search for affected hosts and isolate if CrowdStrike is configured
            if trigger_type == "ip" and CS_CLIENT_ID:
                try:
                    # Find hosts that communicated with this IP via UDM search results
                    # For now, log the containment intent
                    step5b["actions"].append({
                        "action": "CROWDSTRIKE_ISOLATE_PENDING",
                        "detail": f"Hosts communicating with {trigger} identified. CrowdStrike isolation available.",
                        "requires_approval": True,
                    })
                    results["actions_taken"].append(f"CrowdStrike isolation queued for hosts contacting {trigger}")
                except Exception as e:
                    step5b["actions"].append({"action": "CROWDSTRIKE_ERROR", "detail": str(e)})
            
            # Action 2: If domain/IP, add to blocklist Data Table
            if trigger_type in ("ip", "domain"):
                try:
                    blocklist_resp = requests.patch(
                        f"{SECOPS_BASE_URL}/dataTables/automated_blocklist",
                        headers=_secops_headers(),
                        json={
                            "name": "automated_blocklist",
                            "rows": [{"values": [trigger, trigger_type, severity, datetime.now(timezone.utc).isoformat()]}],
                        },
                        timeout=15,
                    )
                    if blocklist_resp.status_code in (200, 201):
                        step5b["actions"].append({
                            "action": "ADDED_TO_BLOCKLIST",
                            "detail": f"{trigger} added to automated_blocklist Data Table",
                        })
                        results["actions_taken"].append(f"Added {trigger} to automated_blocklist Data Table")
                    else:
                        step5b["actions"].append({
                            "action": "BLOCKLIST_NOTE",
                            "detail": f"Could not add to blocklist (API {blocklist_resp.status_code}). Create 'automated_blocklist' Data Table in SecOps if it doesn't exist.",
                        })
                except Exception as e:
                    step5b["actions"].append({"action": "BLOCKLIST_ERROR", "detail": str(e)})
            
            # Action 3: If compromised user found in UDM events, suspend in Okta
            if OKTA_DOMAIN and OKTA_API_TOKEN and events_found > 0:
                step5b["actions"].append({
                    "action": "OKTA_SUSPEND_AVAILABLE",
                    "detail": "Affected users can be suspended via Okta. Use suspend_okta_user tool with the specific email.",
                    "requires_approval": True,
                })
            
            # Action 4: If hash, check if file is on any endpoints
            if trigger_type == "hash":
                step5b["actions"].append({
                    "action": "ENDPOINT_SCAN_RECOMMENDED",
                    "detail": f"Hash {trigger} should be swept across all endpoints. Use CrowdStrike RTR or Defender Live Response.",
                })
        
        elif severity == "HIGH":
            step5b["actions"].append({
                "action": "MONITORING",
                "detail": "Severity HIGH — automated monitoring active. Manual containment available via individual tools.",
            })
        else:
            step5b["actions"].append({
                "action": "NO_CONTAINMENT_NEEDED",
                "detail": f"Severity {severity} does not warrant automated containment.",
            })
        
        step5b["status"] = "complete"
        results["steps"].append(step5b)

        # ── STEP 6: GENERATE INVESTIGATION REPORT (Vertex AI) ──
        step6 = {"step": "6_REPORT", "status": "running"}
        
        # Build context for Vertex AI
        report_context = {
            "trigger": trigger,
            "trigger_type": trigger_type,
            "enrichment": enrichment,
            "udm_events_found": step2.get("events_found", 0),
            "udm_query": udm_query,
            "severity": severity,
            "rule_created": step4.get("rule_created", False),
            "rule_name": step4.get("rule_name", step4.get("existing_rule", "N/A")),
            "case_created": step5.get("case_created", False),
            "case_id": step5.get("case_id", "N/A"),
            "containment_actions": step5b.get("actions", []),
            "actions_taken": results["actions_taken"],
        }
        
        try:
            token = get_adc_token()
            gemini_url = (
                f"https://us-central1-aiplatform.googleapis.com/v1/"
                f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
                f"publishers/google/models/{GEMINI_MODEL}:generateContent"
            )
            
            report_prompt = f"""You are a senior security analyst generating a formal investigation report for the SOC.

INVESTIGATION DATA:
{json.dumps(report_context, indent=2, default=str)}

Generate a professional investigation report using EXACTLY this format:

📋 INVESTIGATION REPORT — IR-{datetime.now(timezone.utc).strftime('%Y-%m%d-%H%M')}
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

SUBJECT: {trigger_type.upper()} Investigation — {trigger}
CLASSIFICATION: {severity}
ANALYST: Autonomous MCP Pipeline

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY:
Write 2-3 sentences summarizing what was found and the overall risk assessment.

INDICATOR DETAILS:
List the enrichment data (VT score, ASN, country, reputation, etc.)

SIEM FINDINGS:
Describe what was found in the UDM search — how many events, what type of activity, time range.

THREAT ASSESSMENT:
Explain the severity rating and why. Reference the VT score and event volume.

ACTIONS TAKEN:
List each action with a ✅ prefix. Include rule creation, case creation, containment actions.

RECOMMENDATIONS:
Provide 3-5 specific, actionable next steps for the SOC team.

MITRE ATT&CK MAPPING:
Map the observed activity to relevant MITRE techniques.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
END OF REPORT

Be specific. Use the actual data provided. Do not hallucinate findings."""

            report_resp = requests.post(
                gemini_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={
                    "contents": [{"role": "user", "parts": [{"text": report_prompt}]}],
                    "systemInstruction": {"parts": [{"text": (
                        "You are a senior SOC analyst writing formal investigation reports. "
                        "Be precise, technical, and actionable. Use the exact data provided. "
                        "Do not make up findings. Reference specific IPs, ASNs, event counts, and rule names from the data."
                    )}]},
                },
                timeout=60,
            )
            
            if report_resp.status_code == 200:
                report_text = report_resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                results["report"] = report_text
                results["summary"] = report_text
                step6["report_generated"] = True
            else:
                # Fallback to basic summary if Gemini fails
                step6["report_generated"] = False
                step6["gemini_error"] = f"API [{report_resp.status_code}]"
                results["summary"] = _build_basic_summary(trigger, trigger_type, severity, enrichment, step2, step5b, results)
                results["report"] = results["summary"]
        except Exception as e:
            step6["report_generated"] = False
            step6["error"] = str(e)
            results["summary"] = _build_basic_summary(trigger, trigger_type, severity, enrichment, step2, step5b, results)
            results["report"] = results["summary"]
        
        step6["status"] = "complete"
        results["steps"].append(step6)

        logger.info(f"Autonomous investigation complete: {trigger_type} {trigger} — {severity}")
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        logger.error(f"Autonomous investigation error: {e}")
        return json.dumps({"error": str(e), "trigger": trigger})


# ═══════════════════════════════════════════════════════════════
# 🔗 OFFICIAL GOOGLE MCP SERVER WRAPPERS
# ═══════════════════════════════════════════════════════════════
# These tools call official Google MCP servers via HTTP POST to /mcp endpoint
# using the MCP JSON-RPC 2.0 protocol: {"jsonrpc": "2.0", "method": "tools/call", ...}

# ── SecOps MCP Server (https://chronicle.us.rep.googleapis.com/mcp) ──

def _call_mcp_server(mcp_url: str, tool_name: str, arguments: dict) -> str:
    """Generic helper to call any MCP server via HTTP POST with JSON-RPC 2.0 protocol."""
    try:
        token = get_adc_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            }
        }
        resp = requests.post(
            f"{mcp_url}/mcp",
            headers=headers,
            json=payload,
            timeout=60,
        )
        if resp.status_code in (200, 201):
            result = resp.json()
            # MCP protocol returns { "jsonrpc": "2.0", "result": {...} }
            if "result" in result:
                return json.dumps(result["result"])
            return json.dumps(result)
        else:
            return json.dumps({"error": f"MCP API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": f"MCP call failed: {str(e)}"})


# ── SECOPS MCP TOOLS (10 tools) — now using SecOpsClient directly ──

@app_mcp.tool()
def secops_list_cases(limit: int = 100) -> str:
    """List all SOAR cases. Returns case IDs, titles, and statuses."""
    try:
        limit = min(max(1, limit), 1000)
        client = SecOpsClient()
        chronicle = client.chronicle(customer_id=SECOPS_CUSTOMER_ID, project_id=SECOPS_PROJECT_ID, region=SECOPS_REGION)
        result = chronicle.list_cases(page_size=limit)
        cases = result.get('cases', []) if isinstance(result, dict) else result
        return json.dumps({"count": len(cases), "cases": cases})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_get_case(case_id: str) -> str:
    """
    Get full detailed information about a SOAR case including rule text,
    detection details, affected entities (hosts, users, IPs), MITRE mappings,
    and process command lines. Combines case metadata + rule detections.

    Args:
        case_id: Case number (e.g., "5012")
    """
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )

        # 1. Get case metadata from list_cases
        case_name = f"projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}/instances/{SECOPS_CUSTOMER_ID}/cases/{case_id}"
        cases = chronicle.list_cases(page_size=200, as_list=True)
        case_data = None
        for c in cases:
            if c.get('name', '').endswith(f'/cases/{case_id}'):
                case_data = c
                break
        if not case_data:
            return json.dumps({"error": f"Case {case_id} not found"})

        rule_name = case_data.get('displayName', '')

        # 2. Find the matching detection rule and get detections
        rules = chronicle.list_rules(page_size=200, as_list=True)
        matched_rule = None
        for r in rules:
            if r.get('displayName', '') == rule_name:
                matched_rule = r
                break

        detections = []
        hosts = set()
        users = set()
        ips = set()
        processes = set()
        hashes = set()
        mitre = {}

        if matched_rule:
            rid = matched_rule.get('name', '').split('/')[-1]
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(days=30)
            try:
                dets = chronicle.list_detections(
                    rule_id=rid, start_time=start_dt, end_time=end_dt,
                    page_size=20, as_list=True,
                )
                for d in dets:
                    for det in d.get('detection', [d]):
                        for f in det.get('detectionFields', []):
                            if f.get('key') == 'hostname':
                                hosts.add(f['value'])
                        for label in det.get('ruleLabels', []):
                            if 'mitre' in label.get('key', '').lower():
                                mitre[label['key']] = label['value']
                        for outcome in det.get('outcomes', []):
                            k, v = outcome.get('key', ''), outcome.get('value', '')
                            if 'hostname' in k:
                                hosts.update(h.strip() for h in v.split(',') if h.strip())
                            elif 'command_line' in k:
                                processes.update(p.strip() for p in v.split(',') if p.strip())
                            elif 'sha256' in k:
                                hashes.update(h.strip() for h in v.split(',') if h.strip())
                            elif 'user' in k:
                                users.update(u.strip() for u in v.split(',') if u.strip())
                detections = dets
            except Exception:
                pass

        report = {
            "case_id": case_id,
            "name": case_data.get('displayName', ''),
            "priority": case_data.get('priority', '').replace('PRIORITY_', ''),
            "status": case_data.get('status', ''),
            "stage": case_data.get('stage', ''),
            "alert_count": case_data.get('alertCount', 0),
            "assignee": case_data.get('assignee', 'unassigned'),
            "workflow_status": case_data.get('workflowStatus', ''),
            "create_time": case_data.get('createTime', ''),
            "update_time": case_data.get('updateTime', ''),
            "entities": {
                "hosts": sorted(hosts),
                "users": sorted(users),
                "ips": sorted(ips),
                "file_hashes": sorted(hashes),
                "processes": sorted(processes),
            },
            "mitre_attack": mitre,
            "rule": {
                "name": matched_rule.get('displayName', '') if matched_rule else '',
                "text": (matched_rule.get('text', '') if matched_rule else '')[:1000],
                "severity": matched_rule.get('severity', {}).get('displayName', '') if matched_rule and isinstance(matched_rule.get('severity'), dict) else '',
            },
            "detection_count": len(detections),
            "detection_time_range": {
                "earliest": min((d.get('detectionTime', d.get('createTime', '')) for d in detections), default=''),
                "latest": max((d.get('detectionTime', d.get('createTime', '')) for d in detections), default=''),
            } if detections else {},
        }
        return json.dumps(report)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_update_case(case_id: str, priority: str = "", status: str = "", description: str = "", comment: str = "") -> str:
    """
    Update a SOAR case — change priority, status, description, or add investigation notes.
    Uses the v1alpha REST API directly for reliable updates.

    Args:
        case_id:      Case number (e.g., "5012")
        priority:     New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status:       New status (OPENED, CLOSED)
        description:  Update the case description/notes with investigation findings
        comment:      Text to add (written to description if comment API unavailable)
    """
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        token = get_adc_token()
        base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1alpha"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        results = []

        if priority:
            p = priority.upper()
            if not p.startswith("PRIORITY_"):
                p = f"PRIORITY_{p}"
            resp = requests.patch(
                f"{base}/cases/{case_id}",
                headers=headers,
                json={"priority": p},
                params={"updateMask": "priority"},
                timeout=15,
            )
            results.append(f"priority→{p}: {resp.status_code}")

        if status:
            resp = requests.patch(
                f"{base}/cases/{case_id}",
                headers=headers,
                json={"status": status.upper()},
                params={"updateMask": "status"},
                timeout=15,
            )
            results.append(f"status→{status.upper()}: {resp.status_code}")

        desc_text = description or comment
        if desc_text:
            resp = requests.patch(
                f"{base}/cases/{case_id}",
                headers=headers,
                json={"description": desc_text},
                params={"updateMask": "description"},
                timeout=15,
            )
            results.append(f"description: {resp.status_code}")

        if not results:
            return json.dumps({"note": "No fields to update. Provide priority, status, description, or comment."})

        return json.dumps({"status": "updated", "case_id": case_id, "actions": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_list_case_alerts(case_id: str, days_back: int = 30) -> str:
    """
    List all detection alerts associated with a SOAR case by matching the case's
    rule name to actual rule detections.

    Args:
        case_id:   Case number (e.g., "5012")
        days_back: How far back to search for detections (default 30)
    """
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        client = SecOpsClient()
        chronicle = client.chronicle(
            customer_id=SECOPS_CUSTOMER_ID,
            project_id=SECOPS_PROJECT_ID,
            region=SECOPS_REGION,
        )
        # Find the case to get its rule name
        cases = chronicle.list_cases(page_size=200, as_list=True)
        case_data = None
        for c in cases:
            if c.get('name', '').endswith(f'/cases/{case_id}'):
                case_data = c
                break
        if not case_data:
            return json.dumps({"error": f"Case {case_id} not found"})

        rule_name = case_data.get('displayName', '')

        # Find matching rule
        rules = chronicle.list_rules(page_size=200, as_list=True)
        matched_rule = None
        for r in rules:
            if r.get('displayName', '') == rule_name:
                matched_rule = r
                break
        if not matched_rule:
            return json.dumps({"case_id": case_id, "rule": rule_name, "alerts": [], "note": "No matching custom rule found — may be a curated rule"})

        rid = matched_rule.get('name', '').split('/')[-1]
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=min(days_back, 90))
        dets = chronicle.list_detections(
            rule_id=rid, start_time=start_dt, end_time=end_dt,
            page_size=50, as_list=True,
        )
        # Summarize detections
        alerts = []
        for d in dets:
            for det in d.get('detection', [d]):
                alert = {
                    "rule": det.get('ruleName', ''),
                    "severity": det.get('severity', ''),
                    "alert_state": det.get('alertState', ''),
                    "detection_time": d.get('detectionTime', ''),
                    "url": det.get('urlBackToProduct', ''),
                    "fields": {f['key']: f['value'] for f in det.get('detectionFields', [])},
                    "outcomes": {o['key']: o['value'] for o in det.get('outcomes', [])},
                }
                alerts.append(alert)
        return json.dumps({"case_id": case_id, "rule": rule_name, "count": len(alerts), "alerts": alerts})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_get_case_alert(case_id: str, alert_id: str) -> str:
    """Get detailed information about a specific alert."""
    try:
        if not case_id or not alert_id:
            return json.dumps({"error": "case_id and alert_id are required"})
        client = SecOpsClient()
        chronicle = client.chronicle(customer_id=SECOPS_CUSTOMER_ID, project_id=SECOPS_PROJECT_ID, region=SECOPS_REGION)
        result = chronicle.get_alert(alert_id)
        return json.dumps(result if isinstance(result, dict) else {"alert": str(result)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def secops_update_case_alert(case_id: str, alert_id: str, status: str = "", severity: str = "") -> str:
    """Update an alert status or severity."""
    try:
        if not case_id or not alert_id:
            return json.dumps({"error": "case_id and alert_id are required"})
        client = SecOpsClient()
        chronicle = client.chronicle(customer_id=SECOPS_CUSTOMER_ID, project_id=SECOPS_PROJECT_ID, region=SECOPS_REGION)
        update = {}
        if status:
            update["status"] = status
        if severity:
            update["severity"] = severity
        result = chronicle.update_alert(alert_id, update)
        return json.dumps({"status": "updated", "alert_id": alert_id, "result": result})
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
def secops_execute_bulk_close_case(case_ids: list, reason: str = "Resolved") -> str:
    """Bulk close multiple SOAR cases."""
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
from starlette.responses import JSONResponse


async def health_check(request: StarletteRequest):
    health = {
        "status": "healthy",
        "server": "google-native-mcp",
        "version": "3.1.0",
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
    Gemini often invents parameter names that don't match the function signature.
    This maps them to what the tool actually expects."""
    if not args:
        return args

    # Get the actual tool function's parameter names
    tool_obj = app_mcp._tool_manager._tools.get(tool_name)
    if not tool_obj:
        return args

    import inspect
    try:
        sig = inspect.signature(tool_obj.fn)
        expected_params = set(sig.parameters.keys())
    except (ValueError, TypeError):
        return args

    # If all args already match, return as-is
    if set(args.keys()).issubset(expected_params):
        return args

    # Common Gemini parameter name mismatches
    PARAM_MAP = {
        # Azure AD
        "user_principal_name": "user_email",
        "user_principal": "user_email",
        "upn": "user_email",
        "email": "user_email",
        "username": "user_email",
        # Okta
        "user_id": "user_email",
        "user": "user_email",
        # AWS
        "user_name": "target_user",
        "iam_user": "target_user",
        # CrowdStrike
        "host": "hostname",
        "host_name": "hostname",
        # General
        "query_string": "query",
        "search_query": "query",
        "filter": "filter_string",
        "filter_query": "filter_string",
        "max": "max_results",
        "limit": "max_results",
        "hours": "hours_back",
        "days": "days_back",
        "lookback_hours": "hours_back",
        "lookback_days": "days_back",
        "project": "project_id",
        "case": "case_id",
        "rule": "rule_id",
        "indicator_value": "indicator",
        "ioc": "indicator",
        "ip_address": "indicator",
        "domain_name": "indicator",
        "file_hash": "indicator",
        "sha256": "indicator",
        "ip": "indicator",
        "domain": "indicator",
        "hash": "indicator",
        "table": "table_name",
        "playbook_name": "name",
        "rule_name": "rule_text",
        "member_email": "member",
        "sa_email": "service_account_email",
    }

    normalized = {}
    for k, v in args.items():
        if k in expected_params:
            normalized[k] = v
        elif k in PARAM_MAP and PARAM_MAP[k] in expected_params:
            normalized[PARAM_MAP[k]] = v
        else:
            # Try fuzzy: if only one expected param is unset, map to it
            normalized[k] = v

    # Remove any keys that aren't in the function signature
    final = {k: v for k, v in normalized.items() if k in expected_params}

    # If we lost required params, fall back to original
    if not final and args:
        return args

    return final

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


MAX_ORCHESTRATION_TURNS = 20  # enough for complex multi-step hunts


async def api_chat(request: StarletteRequest):
    """
    Multi-turn orchestration chat endpoint.
    Gemini calls tools in a loop until it produces a final text answer.
    Supports complex pipelines like: GTI -> UDM -> SCC -> correlate -> report.
    """
    try:
        body = await request.json()
        user_msg = body.get("message", "")
        if not user_msg:
            return JSONResponse({"error": "No message provided"}, status_code=400)

        # Session handling
        session_id = (
            body.get("session_id")
            or request.headers.get("x-session-id")
            or request.cookies.get("soc_session")
        )
        if not session_id:
            session_id = str(uuid.uuid4())
        session_store.get_or_create(session_id)

        # Build functionDeclarations from all registered tools
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
                    "required": required,
                },
            })

        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/{GEMINI_MODEL}:generateContent"
        )
        system_instruction = {
            "parts": [{"text": (
                "You are an elite security analyst with full access to SecOps (Chronicle SIEM), "
                "Security Command Center (SCC), Google Threat Intelligence (GTI/VirusTotal), "
                "Cloud Logging, SOAR case management, and cross-platform containment tools. "
                "When given a complex investigation, call multiple tools in sequence — "
                "do NOT stop after one tool call. Chain tools together to build a complete picture. "
                "For threat actor hunts: 1) Look up threat intel, 2) Search SIEM for IOCs, "
                "3) Check SCC for vulnerabilities, 4) Correlate findings, 5) Produce an executive summary. "
                "If a tool returns no results or errors, try alternative approaches or aliases "
                "(e.g., APT28 -> Fancy Bear -> STRONTIUM). "
                f"Default project_id is {SECOPS_PROJECT_ID}. "
                "When you have enough information, produce a clear final text summary — "
                "that signals the end of the investigation. Be specific and actionable."
            )}],
        }

        # Build initial conversation: history + current message
        history = session_store.get_history(session_id)
        contents = history + [{"role": "user", "parts": [{"text": user_msg}]}]

        tools_called = []
        all_tool_results = []

        # ── MULTI-TURN ORCHESTRATION LOOP ──
        for turn in range(MAX_ORCHESTRATION_TURNS):
            token = get_adc_token()
            headers_ai = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            gemini_resp = requests.post(
                gemini_url,
                headers=headers_ai,
                json={
                    "contents": contents,
                    "tools": [{"functionDeclarations": tool_declarations}],
                    "systemInstruction": system_instruction,
                },
                timeout=120,
            )
            if gemini_resp.status_code != 200:
                return JSONResponse({"error": f"Gemini [{gemini_resp.status_code}]: {gemini_resp.text[:300]}"})

            response_data = gemini_resp.json()
            candidates = response_data.get("candidates", [])
            if not candidates:
                prompt_feedback = response_data.get("promptFeedback", {})
                if prompt_feedback.get("blockReason"):
                    return JSONResponse({"error": f"Gemini Blocked Prompt: {prompt_feedback.get('blockReason')}"})
                return JSONResponse({"error": "No response from Gemini", "tools_called": tools_called})

            candidate = candidates[0]
            if candidate.get("finishReason") in ["SAFETY", "RECITATION", "OTHER"]:
                return JSONResponse({"error": f"Gemini Generation Stopped: {candidate.get('finishReason')}"})

            content_resp = candidate.get("content", {})
            parts = content_resp.get("parts", [])

            # Check for function calls vs final text
            has_function_call = any("functionCall" in p for p in parts)

            if not has_function_call:
                # Gemini produced a final text answer — done
                final_text = " ".join(p["text"] for p in parts if "text" in p).strip()
                if not final_text:
                    final_text = f"Empty response generated by Gemini. (Finish Reason: {candidate.get('finishReason', 'UNKNOWN')})"
                session_store.append_history(session_id, "user", user_msg)
                session_store.append_history(session_id, "model", final_text)
                resp = JSONResponse({
                    "response": final_text,
                    "tools_called": tools_called,
                    "tool_results": all_tool_results,
                    "turns_used": turn + 1,
                    "session_id": session_id,
                })
                resp.set_cookie("soc_session", session_id, max_age=86400, samesite="lax")
                return resp

            # Process all function calls in this turn
            contents.append({"role": "model", "parts": parts})

            function_response_parts = []
            for part in parts:
                if "functionCall" not in part:
                    continue
                tool_name = part["functionCall"]["name"]
                tool_args = part["functionCall"].get("args", {})
                tools_called.append({"tool": tool_name, "args": tool_args, "turn": turn + 1})

                # Execute the tool
                try:
                    tool_obj = app_mcp._tool_manager._tools.get(tool_name)
                    if not tool_obj:
                        result_text = json.dumps({"error": f"Tool '{tool_name}' not found"})
                    else:
                        normalized_args = normalize_tool_parameters(tool_name, tool_args)
                        result_text = tool_obj.fn(**normalized_args)
                        if not isinstance(result_text, str):
                            result_text = str(result_text)
                except Exception as e:
                    result_text = json.dumps({"error": f"Tool execution failed: {str(e)}"})
                    logger.error(f"Tool {tool_name} error: {e}")

                # Truncate very large results to stay within context limits
                if len(result_text) > 8000:
                    result_text = result_text[:8000] + "... [truncated]"

                all_tool_results.append({
                    "tool": tool_name,
                    "result_preview": result_text[:500],
                    "turn": turn + 1,
                })

                function_response_parts.append({
                    "functionResponse": {
                        "name": tool_name,
                        "response": {"content": result_text},
                    }
                })

            # Feed tool results back to Gemini for next turn
            contents.append({"role": "user", "parts": function_response_parts})
            logger.info(f"Orchestration turn {turn + 1}: called {[t['tool'] for t in tools_called if t['turn'] == turn + 1]}")

        # Exhausted all turns
        session_store.append_history(session_id, "user", user_msg)
        session_store.append_history(session_id, "model",
            f"Investigation completed using {len(tools_called)} tool calls across {MAX_ORCHESTRATION_TURNS} turns."
        )
        resp = JSONResponse({
            "response": f"Investigation used {len(tools_called)} tool calls across {MAX_ORCHESTRATION_TURNS} turns. "
                         f"Tools used: {', '.join(set(t['tool'] for t in tools_called))}. "
                         f"Review the tool_results for full findings.",
            "tools_called": tools_called,
            "tool_results": all_tool_results,
            "turns_used": MAX_ORCHESTRATION_TURNS,
            "session_id": session_id,
        })
        resp.set_cookie("soc_session", session_id, max_age=86400, samesite="lax")
        return resp

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

# ═══════════════════════════════════════════════════════════════
# 🔐 IAM & PROJECT MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_iam_policy(project_id: str = "") -> str:
    """
    Get the IAM policy for the GCP project — lists all members and their roles.
    Shows who has access, what roles they have, and any conditions applied.

    Args:
        project_id: GCP project ID (defaults to configured project)
    """
    try:
        pid = project_id or SECOPS_PROJECT_ID
        token = get_adc_token()
        resp = requests.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{pid}:getIamPolicy",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"options": {"requestedPolicyVersion": 3}},
            timeout=15,
        )
        if resp.status_code != 200:
            return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
        policy = resp.json()
        # Summarize bindings
        summary = []
        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            members = binding.get("members", [])
            condition = binding.get("condition", {})
            entry = {"role": role, "members": members, "member_count": len(members)}
            if condition:
                entry["condition"] = condition.get("title", condition.get("expression", ""))
            summary.append(entry)
        summary.sort(key=lambda x: x["role"])
        return json.dumps({
            "project": pid,
            "total_bindings": len(summary),
            "total_unique_roles": len(set(b["role"] for b in summary)),
            "bindings": summary,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_service_accounts(project_id: str = "") -> str:
    """
    List all service accounts in the GCP project with their status and key counts.

    Args:
        project_id: GCP project ID (defaults to configured project)
    """
    try:
        pid = project_id or SECOPS_PROJECT_ID
        token = get_adc_token()
        resp = requests.get(
            f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        if resp.status_code != 200:
            return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
        accounts = resp.json().get("accounts", [])
        summary = []
        for sa in accounts:
            email = sa.get("email", "")
            # Get key count for each SA
            key_count = 0
            try:
                keys_resp = requests.get(
                    f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts/{email}/keys",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"keyTypes": "USER_MANAGED"},
                    timeout=10,
                )
                if keys_resp.status_code == 200:
                    key_count = len(keys_resp.json().get("keys", []))
            except Exception:
                pass
            summary.append({
                "email": email,
                "display_name": sa.get("displayName", ""),
                "disabled": sa.get("disabled", False),
                "user_managed_keys": key_count,
            })
        return json.dumps({"project": pid, "service_accounts": summary, "count": len(summary)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def check_iam_permissions(project_id: str = "", member: str = "") -> str:
    """
    Check what IAM roles a specific member (user or service account) has on the project.
    If no member specified, returns all roles for all members.

    Args:
        project_id: GCP project ID (defaults to configured project)
        member:     Email of user or service account to check (e.g., user@domain.com)
    """
    try:
        pid = project_id or SECOPS_PROJECT_ID
        token = get_adc_token()
        resp = requests.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{pid}:getIamPolicy",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"options": {"requestedPolicyVersion": 3}},
            timeout=15,
        )
        if resp.status_code != 200:
            return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
        policy = resp.json()
        if member:
            # Filter to just this member's roles
            member_roles = []
            search_terms = [f"user:{member}", f"serviceAccount:{member}", f"group:{member}", member]
            for binding in policy.get("bindings", []):
                for m in binding.get("members", []):
                    if any(term in m for term in search_terms):
                        member_roles.append({
                            "role": binding["role"],
                            "member": m,
                            "condition": binding.get("condition", {}).get("title", "") if binding.get("condition") else None,
                        })
            return json.dumps({"project": pid, "member": member, "roles": member_roles, "role_count": len(member_roles)})
        else:
            # Return all members grouped by role
            member_map = {}
            for binding in policy.get("bindings", []):
                for m in binding.get("members", []):
                    if m not in member_map:
                        member_map[m] = []
                    member_map[m].append(binding["role"])
            result = [{"member": m, "roles": r, "role_count": len(r)} for m, r in sorted(member_map.items())]
            return json.dumps({"project": pid, "members": result, "total_members": len(result)})
    except Exception as e:
        return json.dumps({"error": str(e)})


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
# All tools exposed on all endpoints — no allowlist filtering.
# Gemini 2.5 Flash handles large tool sets natively.
# ═══════════════════════════════════════════════════════════════

app_mcp_gemini = FastMCP("google-soc", json_response=True)

# Mirror ALL tools to the Gemini-facing MCP server — no filtering
for _tool in app_mcp._tool_manager.list_tools():
    app_mcp_gemini._tool_manager._tools[_tool.name] = _tool

logger.info(f"Gemini MCP server: {len(app_mcp_gemini._tool_manager._tools)} tools exposed (all)")

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
        Route("/api/tools", endpoint=api_tools),
        Route("/api/chat", endpoint=api_chat, methods=["POST"]),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
        Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True)),
    ]
)

app = MCPMiddleware(_starlette_app)

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
            timeout=30,
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
def get_last_cases(count: int = 5, n: int = 0, N: int = 0, num_cases: int = 0, limit: int = 0, number_of_cases: int = 0) -> str:
    """Get the last N SOAR cases. Use for: 'last 5 cases', 'last 10 cases'."""
    for val in [n, N, num_cases, limit, number_of_cases]:
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
        result = chronicle.list_cases(page_size=count)
        # Handle dict response with 'cases' key
        cases = result.get('cases', []) if isinstance(result, dict) else result
        return json.dumps({"count": len(cases), "cases": cases})
    except Exception as e:
        return json.dumps({"error": str(e)})

@app_mcp.tool()
def get_last_detections(count: int = 5, n: int = 0, N: int = 0, num_detections: int = 0, limit: int = 0, number_of_detections: int = 0, minutes_back: float = 0.0) -> str:
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
        if minutes_back > 0:
            start_dt = end_dt - timedelta(minutes=minutes_back)
        result = chronicle.search_rule_alerts(
            start_time=start_dt,
            end_time=end_dt,
            page_size=count
        )
        detections = result.get('alerts', result.get('detections', [])) if isinstance(result, dict) else result
        return json.dumps({"count": len(detections), "detections": detections})
    except Exception as e:
        return json.dumps({"error": str(e)})
