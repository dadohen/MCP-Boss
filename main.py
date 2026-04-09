"""
Google-Native Autonomous MCP Server — Full Security Operations Suite v2.1
==========================================================================
Complete autonomous security operations toolkit bridging Google Cloud Security
pillars plus third-party containment APIs into a single MCP endpoint.

TOOL CATEGORIES:
  🔍 DISCOVERY & HUNTING
    - get_scc_findings          → Security Command Center vulnerabilities
    - query_cloud_logging       → Cloud Audit Logs
    - search_secops_udm         → Chronicle UDM search (SecOpsClient)
    - list_secops_alerts        → YARA-L alert/detection listing (SecOpsClient)
    - check_ingestion_health    → Unparsed log monitoring

  🧠 INTELLIGENCE & ENRICHMENT
    - enrich_indicator          → GTI / VirusTotal (IP, domain, hash, URL)
    - extract_iocs_from_alerts  → Bulk IOC extraction from alerts
    - vertex_ai_investigate     → Gemini-powered threat analysis

  📋 DATA TABLE MANAGEMENT
    - list_data_tables          → List all Data Tables
    - get_data_table_rows       → Read a Data Table's rows
    - create_data_table         → Create a new Data Table
    - replace_data_table_rows   → Overwrite rows in a Data Table

  🛡️ DETECTION MANAGEMENT
    - list_rules                → List YARA-L rules
    - create_detection_rule     → Create a new YARA-L rule
    - toggle_rule               → Enable or disable a YARA-L rule

  📂 SOAR CASE MANAGEMENT
    - list_soar_cases           → List SOAR cases
    - update_soar_case          → Update priority / add comment / close case

  📧 EMAIL CONTAINMENT
    - purge_email_o365          → Hard-delete email via Microsoft Graph

  🔑 IDENTITY CONTAINMENT
    - suspend_okta_user         → Suspend user + clear sessions in Okta
    - revoke_azure_ad_sessions  → Revoke all Azure AD / Entra ID sessions

  ☁️ CLOUD CREDENTIAL CONTAINMENT
    - revoke_aws_access_keys    → Disable all active AWS IAM access keys
    - revoke_aws_sts_sessions   → Deny pre-existing STS assumed-role sessions
    - revoke_gcp_sa_keys        → Delete all user-managed GCP SA keys

  🖥️ ENDPOINT CONTAINMENT
    - isolate_crowdstrike_host  → Network-isolate a host via CrowdStrike Falcon

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
    GoogleAPICallError, PermissionDenied, NotFound, ResourceExhausted,
)
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta, timezone

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

SECOPS_PROJECT_ID   = os.getenv("SECOPS_PROJECT_ID",   "tito-436719")
SECOPS_CUSTOMER_ID  = os.getenv("SECOPS_CUSTOMER_ID",  "1d49deb2eaa7427ca1d1e78ccaa91c10")
SECOPS_REGION       = os.getenv("SECOPS_REGION",       "us")
GTI_API_KEY         = os.getenv("GTI_API_KEY",         "")

O365_CLIENT_ID      = os.getenv("O365_CLIENT_ID",      "")
O365_CLIENT_SECRET  = os.getenv("O365_CLIENT_SECRET",  "")
O365_TENANT_ID      = os.getenv("O365_TENANT_ID",      "")
OKTA_DOMAIN         = os.getenv("OKTA_DOMAIN",         "")
OKTA_API_TOKEN      = os.getenv("OKTA_API_TOKEN",      "")
AZURE_AD_TENANT_ID  = os.getenv("AZURE_AD_TENANT_ID",  "")
AZURE_AD_CLIENT_ID  = os.getenv("AZURE_AD_CLIENT_ID",  "")
AZURE_AD_CLIENT_SECRET = os.getenv("AZURE_AD_CLIENT_SECRET", "")
AWS_ACCESS_KEY_ID   = os.getenv("SOAR_AWS_KEY",        "")
AWS_SECRET_ACCESS_KEY = os.getenv("SOAR_AWS_SECRET",   "")
CS_CLIENT_ID        = os.getenv("CROWDSTRIKE_CLIENT_ID",    "")
CS_CLIENT_SECRET    = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
CS_BASE_URL         = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

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

TOOL_COUNT = 25
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
        raise RuntimeError("No ADC found. Configure Workload Identity or run: gcloud auth application-default login")
    except RefreshError as e:
        raise RuntimeError(f"ADC token refresh failed: {e}")

def get_chronicle() -> "ChronicleClient":
    """Return a configured SecOpsClient.chronicle instance."""
    from secops import SecOpsClient
    client = SecOpsClient()
    return client.chronicle(
        customer_id=SECOPS_CUSTOMER_ID,
        project_id=SECOPS_PROJECT_ID,
        region=SECOPS_REGION,
    )

def _time_window(hours_back: int = 24, start_time: str = "", end_time: str = ""):
    """Return (start_dt, end_dt) as timezone-aware datetime objects."""
    if start_time and end_time:
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt   = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    else:
        hours_back = min(max(1, hours_back), 8760)
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(hours=hours_back)
    return start_dt, end_dt

def _get_o365_token() -> str:
    if not all([O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET]):
        raise RuntimeError("O365 credentials not configured. Set O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET.")
    resp = requests.post(
        f"https://login.microsoftonline.com/{O365_TENANT_ID}/oauth2/v2.0/token",
        data={"client_id": O365_CLIENT_ID, "client_secret": O365_CLIENT_SECRET,
              "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"O365 token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]

def _get_crowdstrike_token() -> str:
    if not all([CS_CLIENT_ID, CS_CLIENT_SECRET]):
        raise RuntimeError("CrowdStrike credentials not configured.")
    resp = requests.post(f"{CS_BASE_URL}/oauth2/token",
                         data={"client_id": CS_CLIENT_ID, "client_secret": CS_CLIENT_SECRET}, timeout=15)
    if resp.status_code != 201:
        raise RuntimeError(f"CrowdStrike token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]


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
        logs = [{"timestamp": str(e.timestamp), "severity": e.severity, "payload": str(e.payload)[:2000]}
                for e in entries]
        return json.dumps({"cloud_logs": logs, "count": len(logs)})
    except (PermissionDenied, ResourceExhausted, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def search_secops_udm(
    query: str,
    hours_back: int = 24,
    start_time: str = "",
    end_time: str = "",
    max_events: int = 1000,
) -> str:
    """
    Execute a UDM search in Google SecOps / Chronicle using the official SecOps SDK.
    Supports hours_back OR explicit start_time/end_time (ISO 8601 UTC strings).

    Example query: 'metadata.event_type = "NETWORK_CONNECTION" AND target.ip = "1.2.3.4"'
    """
    try:
        if not query or len(query.strip()) < 5:
            return json.dumps({"error": "Query too short (min 5 chars)"})
        start_dt, end_dt = _time_window(hours_back, start_time, end_time)
        chron = get_chronicle()
        result = chron.search_udm(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            max_events=min(max_events, 10000),
        )
        logger.info(f"UDM search: '{query[:60]}' returned {len(result.get('events', []))} events")
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_secops_detections(
    max_results: int = 10,
    hours_back: int = 168,
    start_time: str = "",
    end_time: str = "",
    include_custom_rules: bool = True,
    filter_query: str = "",
) -> str:
    """
    List ALL recent detections from Google SecOps — both custom YARA-L rules AND
    curated/built-in rules. Returns a unified view of every detection that fired,
    sorted by alert count.

    This combines:
      1. Cases (curated + escalated rule detections visible in the UI)
      2. Custom rule detections (from your deployed YARA-L rules)

    Args:
        max_results:          Max detections to return (default 10)
        hours_back:           Look-back window in hours (default 168 = 7 days)
        start_time:           ISO 8601 UTC (overrides hours_back)
        end_time:             ISO 8601 UTC (overrides hours_back)
        include_custom_rules: Also scan custom rules for detections (default True)
        filter_query:         Optional case filter (e.g., 'priority = "HIGH"')
    """
    try:
        chron = get_chronicle()
        start_dt, end_dt = _time_window(hours_back, start_time, end_time)
        detections = []

        # 1. Cases (includes curated rule detections + SOAR escalations)
        cases = chron.list_cases(
            page_size=min(max_results * 2, 200),
            filter_query=filter_query if filter_query else None,
            order_by="updateTime desc",
            as_list=True,
        )
        for c in cases:
            detections.append({
                "rule": c.get("displayName", ""),
                "case_id": c.get("name", "").split("/")[-1],
                "type": "CASE",
                "severity": c.get("priority", "").replace("PRIORITY_", ""),
                "detection_count": c.get("alertCount", 0),
                "stage": c.get("stage", ""),
                "status": c.get("status", ""),
            })

        # 2. Custom rule detections (raw YARA-L hits)
        if include_custom_rules:
            rules = chron.list_rules(page_size=100, as_list=True)
            for rule in rules:
                rid = rule.get("name", "").split("/")[-1]
                name = rule.get("displayName", "")
                sev = rule.get("severity", {})
                sev_name = sev.get("displayName", "") if isinstance(sev, dict) else str(sev)
                try:
                    dets = chron.list_detections(
                        rule_id=rid, start_time=start_dt, end_time=end_dt,
                        page_size=5, as_list=True,
                    )
                    if dets:
                        detections.append({
                            "rule": name,
                            "rule_id": rid,
                            "type": "CUSTOM_RULE",
                            "severity": sev_name,
                            "detection_count": len(dets),
                        })
                except Exception:
                    pass

        # Sort by detection_count desc, return top N
        detections.sort(key=lambda x: x.get("detection_count", 0), reverse=True)
        detections = detections[:max_results]
        logger.info(f"Detections: {len(detections)} returned (cases + custom rules)")
        return json.dumps({"detections": detections, "count": len(detections)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_secops_investigations(max_results: int = 10) -> str:
    """
    List recent SecOps investigations with AI-generated summaries, verdicts,
    and findings. These are the enriched investigation views in the Chronicle UI.

    Args:
        max_results: Number of investigations to return (default 10)
    """
    try:
        chron = get_chronicle()
        result = chron.list_investigations(page_size=min(max_results, 100))
        investigations = result.get("investigations", [])
        summary = []
        for inv in investigations:
            summary.append({
                "id": inv.get("name", "").split("/")[-1],
                "name": inv.get("displayName", ""),
                "verdict": inv.get("verdict", ""),
                "summary": (inv.get("summary", "") or "")[:500],
                "create_time": inv.get("createTime", ""),
                "update_time": inv.get("updateTime", ""),
            })
        logger.info(f"Investigations: {len(summary)} returned")
        return json.dumps({"investigations": summary, "count": len(summary)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def check_ingestion_health(log_type: str = "", hours_back: int = 1) -> str:
    """
    Check for unparsed logs in SecOps to identify silent parser failures.
    If log_type is provided, scopes the check to that log source.
    """
    try:
        query = "raw = /.*/ parsed = false"
        if log_type:
            query += f' log_type = "{log_type}"'
        start_dt, end_dt = _time_window(min(max(1, hours_back), 168))
        chron = get_chronicle()
        result = chron.search_udm(query=query, start_time=start_dt, end_time=end_dt, max_events=1000)
        return json.dumps({"status": "ok", "query": query, "result": result})
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
                result.update({"file_type": attrs.get("type_description"),
                               "file_name": attrs.get("meaningful_name"),
                               "size": attrs.get("size"),
                               "first_seen": attrs.get("first_submission_date")})
            return json.dumps(result)
        elif resp.status_code == 404:
            return json.dumps({"indicator": indicator, "result": "NOT_FOUND", "note": "May be novel/zero-day."})
        return json.dumps({"error": f"GTI [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def extract_iocs_from_alerts(hours_back: int = 24) -> str:
    """
    Bulk extract all IOCs (IPs, domains, hashes, emails) from recent SecOps alerts.
    Returns deduplicated sets ready for blocklist or Data Table population.
    """
    try:
        start_dt, end_dt = _time_window(min(max(1, hours_back), 168))
        chron = get_chronicle()
        # Pull events from UDM for IOC extraction
        data = chron.search_udm(
            query="metadata.event_type != \"GENERIC_EVENT\"",
            start_time=start_dt,
            end_time=end_dt,
            max_events=5000,
        )
        ips, domains, hashes, emails = set(), set(), set(), set()
        for alert in data.get("events", []):
            event = alert.get("udm", alert)
            for event in [event]:
                for field in ("target", "principal", "src", "intermediary"):
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
                    for email in entity.get("user", {}).get("email_addresses", []):
                        emails.add(email.lower())
        result = {
            "ips": sorted(ips), "domains": sorted(domains),
            "hashes": sorted(hashes), "emails": sorted(emails),
            "totals": {"ips": len(ips), "domains": len(domains),
                       "hashes": len(hashes), "emails": len(emails)},
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

Provide:
1) THREAT ASSESSMENT (severity + confidence)
2) KEY FINDINGS
3) ATTACK NARRATIVE
4) RECOMMENDED ACTIONS
5) DETECTION GAPS

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
        chron = get_chronicle()
        result = chron.list_data_tables()
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_data_table_rows(table_name: str) -> str:
    """Read all rows from a specific Data Table."""
    try:
        chron = get_chronicle()
        result = chron.list_data_table_rows(name=table_name)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def create_data_table(name: str, description: str, columns: dict) -> str:
    """
    Create a new Data Table in SecOps.

    Args:
        name:        Table name (e.g., "malicious_ips")
        description: Human-readable description
        columns:     Dict of column_name -> type ("STRING", "CIDR", "REGEX")
                     Example: {"ip": "CIDR", "reason": "STRING"}
    """
    try:
        chron = get_chronicle()
        result = chron.create_data_table(
            name=name,
            description=description,
            header=columns,
        )
        logger.info(f"Data Table created: {name}")
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def replace_data_table_rows(table_name: str, rows: list) -> str:
    """
    Replace all rows in a Data Table.
    Each row is a list of string values matching the table's column order.

    Example: rows=[["1.2.3.4", "C2 server"], ["5.6.7.8", "Scanner"]]
    """
    try:
        chron = get_chronicle()
        result = chron.replace_data_table_rows(name=table_name, rows=rows)
        logger.info(f"Data Table '{table_name}' updated: {len(rows)} rows")
        return json.dumps({"status": "success", "table": table_name, "rows_written": len(rows), "result": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ DETECTION MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def list_rules(page_size: int = 100) -> str:
    """List all YARA-L rules in the SecOps instance with their enabled/disabled status."""
    try:
        chron = get_chronicle()
        result = chron.list_rules(page_size=min(page_size, 1000))
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def create_detection_rule(rule_text: str, enabled: bool = True) -> str:
    """
    Create a new YARA-L 2.0 detection rule in Google SecOps and optionally enable it.

    Args:
        rule_text: Full YARA-L 2.0 rule definition.
        enabled:   Whether to immediately enable the rule after creation (default True).
    """
    try:
        chron = get_chronicle()
        result = chron.create_rule(rule_text=rule_text)
        rule_id = result.get("name", "").split("/")[-1]
        logger.info(f"Rule created: {rule_id}")
        if enabled and rule_id:
            en_result = chron.enable_rule(rule_id=rule_id, enabled=True)
            result["enabled_result"] = en_result
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def toggle_rule(rule_id: str, enabled: bool) -> str:
    """Enable or disable a YARA-L detection rule by its rule ID."""
    try:
        chron = get_chronicle()
        result = chron.enable_rule(rule_id=rule_id, enabled=enabled)
        logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}")
        return json.dumps({"status": "success", "rule_id": rule_id, "enabled": enabled, "result": result})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📂 SOAR CASE MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def list_soar_cases(filter_query: str = "", page_size: int = 25) -> str:
    """
    List SOAR cases in SecOps.

    Args:
        filter_query: Optional filter (e.g., 'status = "OPEN" AND priority = "HIGH"')
        page_size:    Max cases to return (default 25)
    """
    try:
        chron = get_chronicle()
        result = chron.list_cases(
            page_size=min(page_size, 200),
            filter_query=filter_query if filter_query else None,
        )
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_soar_case(
    case_name: str,
    comment: str = "",
    priority: str = "",
    status: str = "",
    close_reason: str = "",
) -> str:
    """
    Update an existing SOAR case — change priority, status, or add a comment.

    Args:
        case_name:    Full case resource name or case ID
        comment:      Text comment to add to the case
        priority:     New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status:       New status (OPEN, IN_PROGRESS, CLOSED)
        close_reason: Required if status=CLOSED
    """
    try:
        chron = get_chronicle()
        patch_data = {}
        update_fields = []
        if priority:
            patch_data["priority"] = priority.upper()
            update_fields.append("priority")
        if status:
            patch_data["status"] = status.upper()
            update_fields.append("status")
            if close_reason:
                patch_data["closeReason"] = close_reason
        if comment:
            patch_data["comment"] = comment
        result = chron.patch_case(
            case_name=case_name,
            case_data=patch_data,
            update_mask=",".join(update_fields) if update_fields else None,
        )
        logger.info(f"SOAR case {case_name} updated")
        return json.dumps({"status": "updated", "case_name": case_name, "result": str(result)})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📧 EMAIL CONTAINMENT
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete") -> str:
    """
    Purge an email from an Office 365 mailbox using Microsoft Graph API.

    Args:
        target_mailbox: User's email address (e.g., user@company.com)
        message_id:     RFC 2822 Message-ID header value
        purge_type:     "hardDelete" (bypasses trash) or "softDelete" (moves to trash)
    """
    try:
        token = _get_o365_token()
        hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        search_resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages",
            headers=hdrs,
            params={"$filter": f"internetMessageId eq '{message_id}'", "$select": "id,subject,from"},
            timeout=15,
        )
        if search_resp.status_code != 200:
            return json.dumps({"error": f"Graph search failed [{search_resp.status_code}]", "detail": search_resp.text[:300]})
        messages = search_resp.json().get("value", [])
        if not messages:
            return json.dumps({"status": "not_found", "detail": f"No email with Message-ID '{message_id}' in {target_mailbox}"})
        internal_id = messages[0]["id"]
        subject = messages[0].get("subject", "unknown")
        if purge_type == "hardDelete":
            del_resp = requests.delete(
                f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}",
                headers=hdrs, timeout=15)
        else:
            del_resp = requests.post(
                f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}/move",
                headers=hdrs, json={"destinationId": "deleteditems"}, timeout=15)
        if del_resp.status_code in (200, 201, 204):
            logger.info(f"O365 purge: {purge_type} '{subject}' from {target_mailbox}")
            return json.dumps({"status": "purged", "mailbox": target_mailbox, "subject": subject, "purge_type": purge_type})
        return json.dumps({"error": f"Purge failed [{del_resp.status_code}]", "detail": del_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"O365 error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 🔑 IDENTITY CONTAINMENT
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def suspend_okta_user(user_email: str, clear_sessions: bool = True) -> str:
    """Suspend a user in Okta and optionally clear all active sessions."""
    try:
        if not all([OKTA_DOMAIN, OKTA_API_TOKEN]):
            return json.dumps({"error": "Okta credentials not configured"})
        hdrs = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Content-Type": "application/json"}
        user_resp = requests.get(f"https://{OKTA_DOMAIN}/api/v1/users/{user_email}", headers=hdrs, timeout=15)
        if user_resp.status_code != 200:
            return json.dumps({"error": f"User not found [{user_resp.status_code}]"})
        user_id = user_resp.json()["id"]
        results = []
        susp = requests.post(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/lifecycle/suspend", headers=hdrs, timeout=15)
        results.append(f"Suspend: {susp.status_code}")
        if clear_sessions:
            sess = requests.delete(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/sessions", headers=hdrs, timeout=15)
            results.append(f"Clear sessions: {sess.status_code}")
        logger.info(f"Okta: {user_email} suspended, sessions cleared={clear_sessions}")
        return json.dumps({"status": "contained", "user": user_email, "actions": results})
    except Exception as e:
        return json.dumps({"error": f"Okta error: {e}"})


@app_mcp.tool()
def revoke_azure_ad_sessions(user_email: str) -> str:
    """Revoke all active sign-in sessions for an Azure AD / Entra ID user."""
    try:
        if not all([AZURE_AD_TENANT_ID, AZURE_AD_CLIENT_ID, AZURE_AD_CLIENT_SECRET]):
            return json.dumps({"error": "Azure AD credentials not configured"})
        token_resp = requests.post(
            f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}/oauth2/v2.0/token",
            data={"client_id": AZURE_AD_CLIENT_ID, "client_secret": AZURE_AD_CLIENT_SECRET,
                  "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
            timeout=15)
        token = token_resp.json()["access_token"]
        resp = requests.post(
            f"https://graph.microsoft.com/v1.0/users/{user_email}/revokeSignInSessions",
            headers={"Authorization": f"Bearer {token}"}, timeout=15)
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
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        disabled = []
        for page in iam.get_paginator("list_access_keys").paginate(UserName=target_user):
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
    Deny all pre-existing STS sessions for an AWS IAM user via a deny-all inline policy.
    Critical: disabling access keys does NOT invalidate already-assumed roles.
    """
    try:
        if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
            return json.dumps({"error": "AWS credentials not configured"})
        import boto3
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}
        }]})
        iam.put_user_policy(UserName=target_user, PolicyName="SOAR_Emergency_Session_Revocation", PolicyDocument=policy)
        logger.info(f"AWS STS sessions revoked for {target_user} (cutoff: {now})")
        return json.dumps({"status": "sessions_revoked", "user": target_user, "cutoff": now})
    except Exception as e:
        return json.dumps({"error": f"AWS STS error: {e}"})


@app_mcp.tool()
def revoke_gcp_sa_keys(project_id: str, service_account_email: str) -> str:
    """Delete all user-managed keys for a GCP service account. Stops leaked SA key abuse."""
    try:
        token = get_adc_token()
        hdrs = {"Authorization": f"Bearer {token}"}
        resource = f"projects/{project_id}/serviceAccounts/{service_account_email}"
        keys_resp = requests.get(
            f"https://iam.googleapis.com/v1/{resource}/keys?keyTypes=USER_MANAGED",
            headers=hdrs, timeout=15)
        if keys_resp.status_code != 200:
            return json.dumps({"error": f"List keys failed [{keys_resp.status_code}]"})
        deleted = []
        for key in keys_resp.json().get("keys", []):
            key_name = key["name"]
            del_resp = requests.delete(f"https://iam.googleapis.com/v1/{key_name}", headers=hdrs, timeout=15)
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
    Network-isolate a host via CrowdStrike Falcon. Provide hostname or device_id.
    The host remains accessible to CrowdStrike cloud for forensics.
    """
    try:
        token = _get_crowdstrike_token()
        hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        if not device_id and hostname:
            search_resp = requests.get(f"{CS_BASE_URL}/devices/queries/devices/v1",
                                       headers=hdrs, params={"filter": f'hostname:"{hostname}"'}, timeout=15)
            if search_resp.status_code == 200:
                ids = search_resp.json().get("resources", [])
                if not ids:
                    return json.dumps({"error": f"No CrowdStrike device found for hostname '{hostname}'"})
                device_id = ids[0]
            else:
                return json.dumps({"error": f"Device search failed [{search_resp.status_code}]"})
        if not device_id:
            return json.dumps({"error": "Provide hostname or device_id"})
        contain_resp = requests.post(
            f"{CS_BASE_URL}/devices/entities/devices-actions/v2?action_name=contain",
            headers=hdrs, json={"ids": [device_id]}, timeout=15)
        if contain_resp.status_code == 202:
            logger.info(f"CrowdStrike: host {device_id} ({hostname}) isolated")
            return json.dumps({"status": "isolated", "device_id": device_id, "hostname": hostname})
        return json.dumps({"error": f"Containment failed [{contain_resp.status_code}]", "detail": contain_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"CrowdStrike error: {e}"})


# ═══════════════════════════════════════════════════════════════
# STARLETTE APP + SSE TRANSPORT
# ═══════════════════════════════════════════════════════════════

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, HTMLResponse
from mcp.server.sse import SseServerTransport


async def health_check(request: StarletteRequest):
    return JSONResponse({
        "status": "healthy",
        "server": "google-native-mcp",
        "version": "2.1.0",
        "tools": TOOL_COUNT,
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
    })


async def index(request: StarletteRequest):
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Google SecOps MCP Server</title>
  <style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family:'SF Mono','Fira Code','Consolas',monospace; background:#0a0a0a; color:#e0e0e0;
            display:flex; justify-content:center; align-items:center; min-height:100vh; }}
    .card {{ background:#111; border:1px solid #333; border-radius:8px; padding:40px; max-width:620px; width:90%; }}
    h1 {{ color:#4caf50; margin-bottom:8px; font-size:1.4em; }}
    .badge {{ background:#1a2a1a; color:#4caf50; border:1px solid #4caf50; border-radius:4px;
              padding:4px 12px; font-size:13px; display:inline-block; margin-bottom:24px; }}
    .item {{ display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #222; font-size:14px; }}
    .label {{ color:#888; }}
    .val {{ color:#fff; }}
    .endpoint {{ background:#1a1a1a; padding:12px; border-radius:4px; font-size:13px; margin-top:20px; color:#aaa; word-break:break-all; }}
  </style>
</head>
<body>
<div class="card">
  <h1>🛡️ Google SecOps MCP Server</h1>
  <div class="badge">✅ {TOOL_COUNT} tools active · v2.1.0</div>
  <div class="item"><span class="label">Project</span><span class="val">{SECOPS_PROJECT_ID}</span></div>
  <div class="item"><span class="label">Region</span><span class="val">{SECOPS_REGION}</span></div>
  <div class="item"><span class="label">Customer ID</span><span class="val">{SECOPS_CUSTOMER_ID[:8]}…</span></div>
  <div class="item"><span class="label">GTI / VirusTotal</span><span class="val">{'✅ configured' if GTI_API_KEY else '⚠️ not configured'}</span></div>
  <div class="item"><span class="label">O365</span><span class="val">{'✅' if O365_CLIENT_ID else '— not configured'}</span></div>
  <div class="item"><span class="label">Okta</span><span class="val">{'✅' if OKTA_DOMAIN else '— not configured'}</span></div>
  <div class="item"><span class="label">Azure AD</span><span class="val">{'✅' if AZURE_AD_CLIENT_ID else '— not configured'}</span></div>
  <div class="item"><span class="label">AWS</span><span class="val">{'✅' if AWS_ACCESS_KEY_ID else '— not configured'}</span></div>
  <div class="item"><span class="label">CrowdStrike</span><span class="val">{'✅' if CS_CLIENT_ID else '— not configured'}</span></div>
  <div class="endpoint">MCP endpoint: <strong>/sse</strong> &nbsp;|&nbsp; Health: <strong>/health</strong></div>
</div>
</body>
</html>"""
    return HTMLResponse(html)


def create_app():
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: StarletteRequest):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await app_mcp._mcp_server.run(
                read_stream,
                write_stream,
                app_mcp._mcp_server.create_initialization_options(),
            )

    return Starlette(routes=[
        Route("/", endpoint=index),
        Route("/health", endpoint=health_check),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ])


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
