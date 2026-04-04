"""
Google-Native Autonomous MCP Server — Full Security Operations Suite
=====================================================================
The complete autonomous security operations toolkit bridging every Google Cloud
Security pillar plus third-party containment APIs into a single MCP endpoint.

TOOL CATEGORIES:
  🔍 DISCOVERY & HUNTING (read-only)
    - get_scc_findings          → Security Command Center vulnerabilities
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

  🛡️ SCC VULNERABILITY & REMEDIATION
    - top_vulnerability_findings → Vulns sorted by Attack Exposure Score
    - get_finding_remediation   → Remediation guidance for a finding

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

56 tools total.

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


# ═══════════════════════════════════════════════════════════════
# 🔍 DISCOVERY & HUNTING
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_scc_findings(project_id: str, severity: str = "CRITICAL", max_results: int = 10) -> str:
    """Fetch ACTIVE vulnerabilities from Security Command Center."""
    try:
        project_id = validate_project_id(project_id)
        max_results = min(max(1, max_results), 50)
        client = securitycenter.SecurityCenterClient()
        findings = client.list_findings(request={
            "parent": f"projects/{project_id}",
            "filter": f'state="ACTIVE" AND severity="{severity.upper()}"',
        })
        results = []
        for i, f in enumerate(findings):
            if i >= max_results:
                break
            results.append({
                "resource": f.finding.resource_name,
                "category": f.finding.category,
                "severity": str(f.finding.severity),
                "create_time": str(f.finding.create_time),
                "external_uri": f.finding.external_uri,
                "description": (f.finding.description or "")[:500],
            })
        logger.info(f"SCC: {len(results)} {severity} findings for {project_id}")
        return json.dumps({"scc_findings": results, "count": len(results)})
    except (PermissionDenied, NotFound, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def query_cloud_logging(project_id: str, filter_string: str, max_results: int = 10) -> str:
    """Query Google Cloud Logging for IAM changes, compute events, and audit trails."""
    try:
        project_id = validate_project_id(project_id)
        if not filter_string or len(filter_string.strip()) < 10:
            return json.dumps({"error": "Filter too broad", "detail": "Minimum 10 chars required."})
        client = cloud_logging.Client(project=project_id)
        entries = client.list_entries(filter_=filter_string, max_results=min(max_results, 50))
        logs = [{"timestamp": str(e.timestamp), "severity": e.severity, "payload": str(e.payload)[:2000]} for e in entries]
        logger.info(f"Cloud Logging: {len(logs)} entries for {project_id}")
        return json.dumps({"cloud_logs": logs, "count": len(logs)})
    except (PermissionDenied, ResourceExhausted, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def search_secops_udm(query: str, hours_back: int = 24) -> str:
    """Execute a UDM search or YARA-L query in Google SecOps (Chronicle)."""
    try:
        if not query or len(query.strip()) < 5:
            return json.dumps({"error": "Query too short"})
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/dashboardQueries:execute",
            headers=_secops_headers(),
            json={"dashboardQuery": {"yaraLQuery": query, "timeRange": {"startTime": start, "endTime": end}}},
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"SecOps API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_secops_detections(hours_back: int = 24, max_results: int = 50) -> str:
    """List recent YARA-L detection alerts with rule names, severity, and outcomes."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/rules:listDetections",
            headers=_secops_headers(),
            json={"page_size": min(max_results, 1000), "start_time": start, "end_time": end},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            detections = []
            for d in data.get("detections", [])[:max_results]:
                det = d.get("detection", {}).get("detection", {})
                detections.append({
                    "rule_name": det.get("ruleName", "unknown"),
                    "severity": det.get("severity", "unknown"),
                    "detection_time": d.get("detectionTime", ""),
                    "outcomes": det.get("outcomes", {}),
                })
            return json.dumps({"detections": detections, "count": len(detections)})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def check_ingestion_health(log_type: str = "", hours_back: int = 1) -> str:
    """
    Check for unparsed logs in SecOps. If log_type is provided, checks that specific source.
    Returns unparsed volume to identify silent parser failures.
    """
    try:
        query = 'raw = /.*/ parsed = false'
        if log_type:
            query += f' log_type = "{log_type}"'
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/dashboardQueries:execute",
            headers=_secops_headers(),
            json={"dashboardQuery": {"yaraLQuery": query, "timeRange": {"startTime": start, "endTime": end}}},
            timeout=30,
        )
        if resp.status_code == 200:
            return json.dumps({"status": "ok", "query": query, "result": resp.json()})
        return json.dumps({"error": f"API [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🧠 INTELLIGENCE & ENRICHMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def enrich_indicator(indicator: str, indicator_type: str = "auto") -> str:
    """Enrich an IP, domain, URL, or file hash using Google Threat Intel / VirusTotal."""
    try:
        indicator = validate_indicator(indicator)
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})

        if indicator_type == "auto":
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
                indicator_type = "ip"
            elif re.match(r"^[a-fA-F0-9]{32}$", indicator) or re.match(r"^[a-fA-F0-9]{64}$", indicator):
                indicator_type = "hash"
            elif "/" in indicator or "http" in indicator.lower():
                indicator_type = "url"
            else:
                indicator_type = "domain"

        vt = "https://www.virustotal.com/api/v3"
        urls = {"ip": f"{vt}/ip_addresses/{indicator}", "domain": f"{vt}/domains/{indicator}",
                "hash": f"{vt}/files/{indicator}", "url": f"{vt}/search?query={indicator}"}
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
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"page_size": 1000, "start_time": start, "end_time": end}
        ips, domains, hashes, emails = set(), set(), set(), set()
        page_count = 0

        while True:
            resp = requests.post(f"{SECOPS_BASE_URL}/rules:listDetections",
                                 headers=_secops_headers(), json=payload, timeout=30)
            if resp.status_code != 200:
                break
            data = resp.json()
            page_count += 1
            for det in data.get("detections", []):
                for elem in det.get("collectionElements", []):
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
            token = data.get("nextPageToken")
            if not token:
                break
            payload["page_token"] = token

        result = {
            "ips": sorted(ips), "domains": sorted(domains),
            "hashes": sorted(hashes), "emails": sorted(emails),
            "totals": {"ips": len(ips), "domains": len(domains), "hashes": len(hashes), "emails": len(emails)},
            "pages_processed": page_count,
        }
        logger.info(f"IOC extraction: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes, {len(emails)} emails")
        return json.dumps(result)
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
        resp = requests.get(f"{SECOPS_BASE_URL}/dataTables", headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_data_table(table_name: str) -> str:
    """Read the contents of a specific Data Table."""
    try:
        resp = requests.get(f"{SECOPS_BASE_URL}/dataTables/{table_name}",
                            headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
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
        payload = {
            "name": table_name,
            "rows": [{"values": row if isinstance(row, list) else [row]} for row in rows],
        }
        if description:
            payload["description"] = description
        resp = requests.patch(f"{SECOPS_BASE_URL}/dataTables/{table_name}",
                              headers=_secops_headers(), json=payload, timeout=30)
        if resp.status_code == 200:
            logger.info(f"Data Table '{table_name}' updated: {len(rows)} rows")
            return json.dumps({"status": "success", "table": table_name, "rows_written": len(rows)})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ DETECTION MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_rules(page_size: int = 100) -> str:
    """List all YARA-L rules in the SecOps instance with their enabled/disabled status."""
    try:
        resp = requests.get(f"{SECOPS_BASE_URL}/rules",
                            headers=_secops_headers(), params={"pageSize": page_size}, timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]"})
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
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"O365 purge error: {e}"})


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
def revoke_gcp_sa_keys(project_id: str, service_account_email: str) -> str:
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
        resp = requests.post(
            f"{SECOPS_BASE_URL}/cases",
            headers=_secops_headers(),
            json={
                "displayName": title,
                "description": description,
                "priority": priority.upper(),
                "alertSource": alert_source,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info(f"SOAR case created: {title}")
            return resp.text
        return json.dumps({"error": f"Case creation failed [{resp.status_code}]", "detail": resp.text[:500]})
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
        case_id: The case identifier
        comment: Text to add to the case wall
        priority: New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status: New status (OPEN, IN_PROGRESS, CLOSED)
        close_reason: Required when status=CLOSED
    """
    try:
        results = []

        if comment:
            resp = requests.post(
                f"{SECOPS_BASE_URL}/cases/{case_id}/comments",
                headers=_secops_headers(),
                json={"body": comment},
                timeout=15,
            )
            results.append(f"Comment: {resp.status_code}")

        if priority:
            resp = requests.patch(
                f"{SECOPS_BASE_URL}/cases/{case_id}",
                headers=_secops_headers(),
                json={"priority": priority.upper()},
                timeout=15,
            )
            results.append(f"Priority: {resp.status_code}")

        if status:
            body = {"status": status.upper()}
            if close_reason:
                body["closeReason"] = close_reason
            resp = requests.patch(
                f"{SECOPS_BASE_URL}/cases/{case_id}",
                headers=_secops_headers(),
                json=body,
                timeout=15,
            )
            results.append(f"Status: {resp.status_code}")

        logger.info(f"SOAR case {case_id} updated: {results}")
        return json.dumps({"status": "updated", "case_id": case_id, "actions": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🔎 NATURAL LANGUAGE SECURITY SEARCH (SecOps)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def search_security_events(text: str, hours_back: int = 24, max_events: int = 100) -> str:
    """Search security events using natural language. Translates text to a UDM query via Gemini, then executes the search in SecOps."""
    try:
        if not text or len(text.strip()) < 3:
            return json.dumps({"error": "Search text too short"})
        hours_back = min(max(1, hours_back), 8760)
        max_events = min(max(1, max_events), 10000)

        # Step 1: Use Gemini to translate natural language to UDM query
        token = get_adc_token()
        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/gemini-2.0-flash:generateContent"
        )
        translate_prompt = (
            "You are a Google SecOps UDM query expert. Convert the following natural language "
            "security search into a valid UDM Search query. Return ONLY the raw UDM query string, "
            "nothing else. No markdown, no explanation.\n\n"
            f"Natural language: {text}\n\nUDM Query:"
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

        # Step 2: Execute the UDM search
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/dashboardQueries:execute",
            headers=_secops_headers(),
            json={"dashboardQuery": {"yaraLQuery": udm_query, "timeRange": {"startTime": start, "endTime": end}}},
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", data.get("results", []))[:max_events]
            return json.dumps({"natural_language_query": text, "udm_query": udm_query, "events": events, "count": len(events)})
        return json.dumps({"error": f"SecOps search failed [{resp.status_code}]", "udm_query": udm_query, "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🚨 SECURITY ALERTS & ENTITY LOOKUP (SecOps)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_security_alerts(hours_back: int = 24, max_alerts: int = 10) -> str:
    """Retrieve recent security alerts from Google SecOps with time filtering."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        max_alerts = min(max(1, max_alerts), 1000)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.get(
            f"{SECOPS_BASE_URL}/alerts",
            headers=_secops_headers(),
            params={"startTime": start, "endTime": end, "pageSize": max_alerts},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            alerts = data.get("alerts", [])
            formatted = []
            for a in alerts[:max_alerts]:
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
            timeout=30,
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
def get_file_report(hash: str) -> str:
    """Get a comprehensive file analysis report from VirusTotal/GTI by file hash (MD5, SHA-1, or SHA-256). Returns detection stats, file type, names, and behavioral summary."""
    try:
        if not hash or not re.match(r"^[a-fA-F0-9]{32,64}$", hash):
            return json.dumps({"error": "Invalid hash format. Provide MD5, SHA-1, or SHA-256."})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "hash": hash,
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
def get_domain_report(domain: str) -> str:
    """Get a comprehensive domain analysis report from VirusTotal/GTI. Returns reputation, registrar, DNS records, and detection stats."""
    try:
        if not domain or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", domain):
            return json.dumps({"error": "Invalid domain format"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "domain": domain,
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
def get_ip_report(ip_address: str) -> str:
    """Get a comprehensive IP address analysis report from VirusTotal/GTI. Returns ASN, country, reputation, and detection stats."""
    try:
        if not ip_address or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            return json.dumps({"error": "Invalid IPv4 address format"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": GTI_API_KEY},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            return json.dumps({
                "ip_address": ip_address,
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
def search_threat_actors(query: str, limit: int = 10) -> str:
    """Search for threat actor profiles in VirusTotal/GTI intelligence. Returns matching threat actor names, descriptions, and associated indicators."""
    try:
        if not query or len(query.strip()) < 2:
            return json.dumps({"error": "Query too short"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        limit = min(max(1, limit), 50)
        search_query = f'collection_type:"threat-actor" AND {query}'
        resp = requests.get(
            "https://www.virustotal.com/api/v3/intelligence/search",
            headers={"x-apikey": GTI_API_KEY},
            params={"query": search_query, "limit": limit},
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
        return json.dumps({"error": f"GTI search [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def search_malware_families(query: str, limit: int = 10) -> str:
    """Search for malware family profiles in VirusTotal/GTI intelligence. Returns matching family names, descriptions, and classification."""
    try:
        if not query or len(query.strip()) < 2:
            return json.dumps({"error": "Query too short"})
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})
        limit = min(max(1, limit), 50)
        search_query = f'collection_type:"malware-family" AND {query}'
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
def top_vulnerability_findings(project_id: str, max_findings: int = 20) -> str:
    """Get top vulnerability findings from Security Command Center sorted by Attack Exposure Score. Returns findings with severity, category, resource, and remediation priority."""
    try:
        project_id = validate_project_id(project_id)
        max_findings = min(max(1, max_findings), 100)
        client = securitycenter.SecurityCenterClient()
        findings = client.list_findings(request={
            "parent": f"projects/{project_id}",
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
def get_finding_remediation(project_id: str, finding_id: str) -> str:
    """Get detailed remediation guidance for a specific SCC finding. Returns next steps, affected resource context, and Cloud Asset Inventory info if available."""
    try:
        project_id = validate_project_id(project_id)
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
        resp = requests.get(
            f"{SECOPS_BASE_URL}/cases",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            cases = data.get("cases", [])
            formatted = []
            for c in cases:
                formatted.append({
                    "id": c.get("name", c.get("caseId", "")),
                    "title": c.get("displayName", c.get("title", "")),
                    "priority": c.get("priority", ""),
                    "status": c.get("status", ""),
                    "create_time": c.get("createTime", ""),
                    "update_time": c.get("updateTime", ""),
                    "assignee": c.get("assignee", ""),
                })
            return json.dumps({"cases": formatted, "count": len(formatted)})
        return json.dumps({"error": f"Cases API [{resp.status_code}]", "detail": resp.text[:500]})
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
def list_log_entries(project_id: str, filter_string: str, order_by: str = "timestamp desc", page_size: int = 20) -> str:
    """Query Cloud Logging entries using Log Query Language (LQL). Supports SIEM audit logs, SOAR playbook errors, IAM changes, and any GCP service logs."""
    try:
        project_id = validate_project_id(project_id)
        if not filter_string or len(filter_string.strip()) < 3:
            return json.dumps({"error": "filter_string is required"})
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
def list_log_names(project_id: str) -> str:
    """List all available log names in a GCP project. Useful for discovering what log sources exist before querying."""
    try:
        project_id = validate_project_id(project_id)
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"https://logging.googleapis.com/v2/projects/{project_id}/logs",
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            log_names = data.get("logNames", [])
            logger.info(f"Cloud Logging: {len(log_names)} log names for {project_id}")
            return json.dumps({"log_names": log_names, "count": len(log_names)})
        return json.dumps({"error": f"Logging API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_log_buckets(project_id: str) -> str:
    """List all Cloud Logging storage buckets and their retention policies."""
    try:
        project_id = validate_project_id(project_id)
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
def get_log_bucket(project_id: str, bucket_id: str, location: str = "global") -> str:
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
def list_log_views(project_id: str, bucket_id: str = "_Default", location: str = "global") -> str:
    """List log views within a Cloud Logging bucket. Views control access to subsets of log data."""
    try:
        project_id = validate_project_id(project_id)
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
def query_secops_audit_logs(project_id: str, hours_back: int = 24, log_type: str = "siem") -> str:
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
def list_data_access_labels() -> str:
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
def list_data_access_scopes() -> str:
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
def list_parsers() -> str:
    """List all configured parsers and log types in SecOps. Shows which log sources have active parsers."""
    try:
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/logTypes",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def validate_parser(log_type: str, raw_log_sample: str) -> str:
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
def list_feeds() -> str:
    """List all configured data feeds in SecOps. Shows feed status, type, and last poll time."""
    try:
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/feeds",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_feed(feed_id: str) -> str:
    """Get details of a specific feed including its configuration, status, and last ingestion time."""
    try:
        if not feed_id:
            return json.dumps({"error": "feed_id is required"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/feeds/{feed_id}",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📊 INGESTION METRICS
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def query_ingestion_stats(hours_back: int = 24) -> str:
    """Query ingestion volume statistics by product and source. Shows total events ingested per log source."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        v1beta_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1beta"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.post(
            f"{v1beta_base}:queryProductSourceStats",
            headers=_secops_headers(),
            json={"timeRange": {"startTime": start, "endTime": end}},
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
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
def list_rule_errors(rule_id: str) -> str:
    """List errors for a specific YARA-L rule. Shows compilation failures, timeout errors, and execution issues."""
    try:
        if not rule_id:
            return json.dumps({"error": "rule_id is required"})
        v1_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1_base}/rules/{rule_id}/deployments",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📂 CASE MANAGEMENT (expanded)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_case_comments(case_id: str, page_size: int = 50) -> str:
    """List all comments for a SOAR case with full history and filtering support."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        page_size = min(max(1, page_size), 200)
        resp = requests.get(
            f"{SECOPS_BASE_URL}/cases/{case_id}/comments",
            headers=_secops_headers(),
            params={"pageSize": page_size},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_case_priority(case_id: str, priority: str) -> str:
    """Update the priority of a SOAR case. Priority options: PRIORITY_INFO, PRIORITY_LOW, PRIORITY_MEDIUM, PRIORITY_HIGH, PRIORITY_CRITICAL."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        valid_priorities = ["PRIORITY_INFO", "PRIORITY_LOW", "PRIORITY_MEDIUM", "PRIORITY_HIGH", "PRIORITY_CRITICAL"]
        priority = priority.upper()
        if priority not in valid_priorities:
            return json.dumps({"error": f"Invalid priority. Must be one of: {', '.join(valid_priorities)}"})
        resp = requests.patch(
            f"{SECOPS_BASE_URL}/cases/{case_id}",
            headers=_secops_headers(),
            json={"priority": priority},
            timeout=15,
        )
        if resp.status_code == 200:
            logger.info(f"Case {case_id} priority updated to {priority}")
            return json.dumps({"status": "updated", "case_id": case_id, "priority": priority})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def close_case(case_id: str, reason: str = "Resolved") -> str:
    """Close a SOAR case with a resolution reason."""
    try:
        if not case_id:
            return json.dumps({"error": "case_id is required"})
        resp = requests.patch(
            f"{SECOPS_BASE_URL}/cases/{case_id}",
            headers=_secops_headers(),
            json={"status": "CLOSED", "closeReason": reason},
            timeout=15,
        )
        if resp.status_code == 200:
            logger.info(f"Case {case_id} closed with reason: {reason}")
            return json.dumps({"status": "closed", "case_id": case_id, "reason": reason})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📈 DASHBOARDS / OVERVIEW
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_case_overview() -> str:
    """Get case overview dashboard data: total cases, open vs closed, by priority, by assignee."""
    try:
        v1beta_base = (
            f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1beta"
            f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
            f"/instances/{SECOPS_CUSTOMER_ID}"
        )
        resp = requests.get(
            f"{v1beta_base}/cases:getCaseOverviewData",
            headers=_secops_headers(),
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


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
                
                search_resp = requests.post(
                    f"{SECOPS_BASE_URL}/dashboardQueries:execute",
                    headers=_secops_headers(),
                    json={"dashboardQuery": {"yaraLQuery": udm_query, "timeRange": {"startTime": start, "endTime": end}}},
                    timeout=60,
                )
                if search_resp.status_code == 200:
                    search_results = search_resp.json()
                    step2["events_found"] = len(search_results.get("events", search_results.get("rows", [])))
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

        # ── STEP 6: GENERATE SUMMARY ──
        step6 = {"step": "6_REPORT", "status": "running"}
        
        summary_lines = [
            f"🔍 AUTONOMOUS INVESTIGATION COMPLETE",
            f"",
            f"Trigger: {trigger_type.upper()} — {trigger}",
            f"Severity: {severity}",
            f"",
            f"📊 Enrichment:",
        ]
        
        if enrichment.get("malicious_count") is not None:
            summary_lines.append(f"  VT Score: {enrichment.get('malicious_count', 'N/A')}/{enrichment.get('total_engines', 'N/A')} malicious")
        if enrichment.get("country"):
            summary_lines.append(f"  Country: {enrichment.get('country', 'N/A')}")
        if enrichment.get("asn"):
            summary_lines.append(f"  ASN: {enrichment.get('asn', 'N/A')}")
        if enrichment.get("result") == "NOT_FOUND":
            summary_lines.append(f"  ⚠️ NOT IN VT DATABASE — Potential zero-day")
        
        summary_lines.append(f"")
        summary_lines.append(f"🔎 UDM Search: {events_found} events found (72h window)")
        if udm_query:
            summary_lines.append(f"  Query: {udm_query}")
        
        summary_lines.append(f"")
        summary_lines.append(f"⚡ Actions Taken:")
        if results["actions_taken"]:
            for action in results["actions_taken"]:
                summary_lines.append(f"  ✅ {action}")
        else:
            summary_lines.append(f"  ℹ️ No automated actions required (severity={severity})")
        
        results["summary"] = "\n".join(summary_lines)
        step6["status"] = "complete"
        results["steps"].append(step6)

        logger.info(f"Autonomous investigation complete: {trigger_type} {trigger} — {severity}")
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        logger.error(f"Autonomous investigation error: {e}")
        return json.dumps({"error": str(e), "trigger": trigger})


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
        "version": "2.0.0",
        "tools": 56,
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
from starlette.routing import Mount
from starlette.responses import Response
from starlette.staticfiles import StaticFiles

from mcp.server.transport_security import TransportSecuritySettings
import pathlib

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
    # Must return Response to avoid NoneType error on client disconnect
    return Response()


async def api_tools(request: StarletteRequest):
    """Return list of available tools as JSON for the web UI."""
    tool_list = []
    for tool in app_mcp._tool_manager.list_tools():
        tool_list.append({"name": tool.name, "description": tool.description or ""})
    return JSONResponse(tool_list)


async def api_chat(request: StarletteRequest):
    """
    Chat endpoint: takes natural language, uses Gemini to pick a tool,
    calls it, and returns the result with a summary.
    """
    try:
        body = await request.json()
        user_msg = body.get("message", "")
        if not user_msg:
            return JSONResponse({"error": "No message provided"}, status_code=400)

        tools_desc = "\n".join(
            [f"- {t.name}: {t.description}" for t in app_mcp._tool_manager.list_tools()]
        )

        token = get_adc_token()
        gemini_url = (
            f"https://us-central1-aiplatform.googleapis.com/v1/"
            f"projects/{SECOPS_PROJECT_ID}/locations/us-central1/"
            f"publishers/google/models/gemini-2.0-flash:generateContent"
        )
        headers_ai = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        gemini_resp = requests.post(
            gemini_url, headers=headers_ai,
            json={
                "contents": [{"role": "user", "parts": [{"text": user_msg}]}],
                "systemInstruction": {"parts": [{"text": (
                    "You are a security analyst. Available tools:\n"
                    f"{tools_desc}\n\n"
                    "If the user needs a tool, respond with ONLY valid JSON:\n"
                    '{"tool": "tool_name", "args": {"param": "value"}}\n\n'
                    "If no tool is needed, answer directly.\n"
                    f"Default project_id is {SECOPS_PROJECT_ID} unless specified."
                )}]},
            },
            timeout=30,
        )
        if gemini_resp.status_code != 200:
            return JSONResponse({"error": f"Gemini [{gemini_resp.status_code}]: {gemini_resp.text[:300]}"})

        ai_text = gemini_resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()

        if "{" in ai_text and '"tool"' in ai_text:
            start = ai_text.index("{")
            end = ai_text.rindex("}") + 1
            call = json.loads(ai_text[start:end])
            tool_name = call["tool"]
            tool_args = call.get("args", {})

            result = await app_mcp._tool_manager.call_tool(tool_name, tool_args)
            result_text = result[0].text if result else "No result"

            try:
                result_data = json.loads(result_text)
            except (json.JSONDecodeError, TypeError):
                result_data = result_text

            # Summarize
            try:
                sum_resp = requests.post(
                    gemini_url, headers={"Authorization": f"Bearer {get_adc_token()}", "Content-Type": "application/json"},
                    json={"contents": [{"role": "user", "parts": [{"text": (
                        f"User asked: {user_msg}\nTool {tool_name} returned:\n{result_text[:3000]}\nSummarize concisely."
                    )}]}]},
                    timeout=30,
                )
                summary = sum_resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                summary = "Results returned."

            return JSONResponse({"tool_called": tool_name, "tool_args": tool_args, "tool_result": result_data, "response": summary})
        else:
            return JSONResponse({"response": ai_text})

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


STATIC_DIR = pathlib.Path(__file__).parent / "static"

app = Starlette(
    routes=[
        Route("/health", endpoint=health_check),
        Route("/api/tools", endpoint=api_tools),
        Route("/api/chat", endpoint=api_chat, methods=["POST"]),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
        Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True)),
    ]
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
