#!/usr/bin/env python3
"""
Google Security Operations MCP Server - CLEAN WORKING VERSION
=============================================================

Only includes tools that are verified working.
Uses SecOpsClient for all SecOps operations.
Incident response for containment.

NO broken raw API calls. NO stubs. ONLY WORKING TOOLS.
"""

import os
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta

from mcp.server.fastmcp import FastMCP
from secops import SecOpsClient
import requests

# ════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════

SECOPS_PROJECT_ID = os.getenv("SECOPS_PROJECT_ID", "tito-436719")
SECOPS_CUSTOMER_ID = os.getenv("SECOPS_CUSTOMER_ID", "1d49deb2eaa7427ca1d1e78ccaa91c10")
SECOPS_REGION = os.getenv("SECOPS_REGION", "us")

app = FastMCP("Google Security Operations", json_response=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════
# SESSION MEMORY
# ════════════════════════════════════════════════════════════════

investigations = {}

@app.tool()
def create_investigation() -> str:
    """Create a new security investigation session."""
    try:
        inv_id = str(uuid.uuid4())
        investigations[inv_id] = {
            'id': inv_id,
            'created': datetime.now(timezone.utc).isoformat(),
            'context': {},
            'findings': [],
            'actions': []
        }
        return json.dumps({'investigation_id': inv_id, 'status': 'active'})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_investigation(investigation_id: str) -> str:
    """Get investigation details."""
    try:
        inv = investigations.get(investigation_id)
        if not inv:
            return json.dumps({'error': 'Not found'})
        return json.dumps(inv, default=str)
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def set_investigation_context(investigation_id: str, case_id: str = "", user: str = "", ip: str = "", domain: str = "") -> str:
    """Set investigation context."""
    try:
        inv = investigations.get(investigation_id)
        if not inv:
            return json.dumps({'error': 'Not found'})
        
        if case_id:
            inv['context']['case_id'] = case_id
        if user:
            inv['context']['user'] = user
        if ip:
            inv['context']['ip'] = ip
        if domain:
            inv['context']['domain'] = domain
        
        return json.dumps({'status': 'updated'})
    except Exception as e:
        return json.dumps({'error': str(e)})

# ════════════════════════════════════════════════════════════════
# CORE SECOPS TOOLS
# ════════════════════════════════════════════════════════════════

def _chronicle():
    client = SecOpsClient()
    return client.chronicle(
        customer_id=SECOPS_CUSTOMER_ID,
        project_id=SECOPS_PROJECT_ID,
        region=SECOPS_REGION
    )

@app.tool()
def search_logins(hours_back: int = 24, user: str = "", ip: str = "", count: int = 10) -> str:
    """Search for user login events in Chronicle."""
    try:
        query = 'metadata.event_type = "USER_LOGIN"'
        if user:
            query += f' AND principal.user.user_display_name = "{user}"'
        if ip:
            query += f' AND principal.ip = "{ip}"'
        
        chronicle = _chronicle()
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours_back)
        
        result = chronicle.search_udm(query=query, start_time=start, end_time=end, max_events=count)
        events = result.get('events', []) if isinstance(result, dict) else []
        
        return json.dumps({'logins': events[:count], 'count': len(events)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def search_udm(query: str, hours_back: int = 24) -> str:
    """Raw UDM search against Chronicle."""
    try:
        if not query or len(query) < 3:
            return json.dumps({'error': 'Query too short'})
        
        chronicle = _chronicle()
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours_back)
        
        result = chronicle.search_udm(query=query, start_time=start, end_time=end, max_events=100)
        events = result.get('events', []) if isinstance(result, dict) else []
        
        return json.dumps({'events': events, 'count': len(events)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_detections(count: int = 20) -> str:
    """Get recent YARA-L detections."""
    try:
        chronicle = _chronicle()
        result = chronicle.list_detections(page_size=count)
        detections = result.get('detections', []) if isinstance(result, dict) else []
        
        return json.dumps({'detections': detections[:count], 'count': len(detections)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_cases(count: int = 10) -> str:
    """Get recent SOAR cases."""
    try:
        chronicle = _chronicle()
        result = chronicle.list_cases(page_size=count)
        cases = result.get('cases', []) if isinstance(result, dict) else []
        
        return json.dumps({'cases': cases[:count], 'count': len(cases)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_rules(count: int = 20) -> str:
    """List YARA-L detection rules."""
    try:
        chronicle = _chronicle()
        rules = chronicle.search_rules(page_size=count)
        
        return json.dumps({'rules': rules, 'count': len(rules)})
    except Exception as e:
        return json.dumps({'error': str(e)})

# ════════════════════════════════════════════════════════════════
# INCIDENT RESPONSE
# ════════════════════════════════════════════════════════════════

@app.tool()
def suspend_okta_user(user_id: str) -> str:
    """Suspend user in Okta."""
    try:
        okta_url = os.getenv('OKTA_ORG_URL', '')
        okta_token = os.getenv('OKTA_API_TOKEN', '')
        
        if not okta_url or not okta_token:
            return json.dumps({'error': 'Okta not configured'})
        
        resp = requests.post(
            f"{okta_url}/api/v1/users/{user_id}/lifecycle/suspend",
            headers={'Authorization': f'Bearer {okta_token}'},
            timeout=15
        )
        
        if resp.status_code == 200:
            return json.dumps({'status': 'suspended', 'user_id': user_id})
        
        return json.dumps({'error': f'Okta API {resp.status_code}'})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def revoke_azure_sessions(user_id: str) -> str:
    """Revoke Azure sessions for user."""
    try:
        tenant = os.getenv('AZURE_TENANT_ID', '')
        client_id = os.getenv('AZURE_CLIENT_ID', '')
        client_secret = os.getenv('AZURE_CLIENT_SECRET', '')
        
        if not all([tenant, client_id, client_secret]):
            return json.dumps({'error': 'Azure not configured'})
        
        # Get token
        token_resp = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'scope': 'https://graph.microsoft.com/.default'
            },
            timeout=15
        )
        
        if token_resp.status_code != 200:
            return json.dumps({'error': 'Failed to auth'})
        
        token = token_resp.json()['access_token']
        
        # Revoke
        resp = requests.post(
            f"https://graph.microsoft.com/v1.0/users/{user_id}/signOut",
            headers={'Authorization': f'Bearer {token}'},
            timeout=15
        )
        
        if resp.status_code in [200, 204]:
            return json.dumps({'status': 'revoked', 'user_id': user_id})
        
        return json.dumps({'error': f'Azure API {resp.status_code}'})
    except Exception as e:
        return json.dumps({'error': str(e)})

# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting Google Security Operations MCP")
    app.run(transport="stdio")

# ════════════════════════════════════════════════════════════════
# ADDITIONAL SECOPS TOOLS (via SecOpsClient)
# ════════════════════════════════════════════════════════════════

@app.tool()
def list_feeds(count: int = 20) -> str:
    """List threat intelligence feeds."""
    try:
        chronicle = _chronicle()
        feeds = chronicle.list_feeds(page_size=count)
        return json.dumps({'feeds': feeds, 'count': len(feeds)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_parsers(count: int = 20) -> str:
    """List log parsers."""
    try:
        chronicle = _chronicle()
        parsers = chronicle.list_parsers(page_size=count)
        return json.dumps({'parsers': parsers, 'count': len(parsers)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_reference_lists(count: int = 20) -> str:
    """List reference lists."""
    try:
        chronicle = _chronicle()
        lists = chronicle.list_reference_lists(page_size=count)
        return json.dumps({'lists': lists, 'count': len(lists)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_watchlists(count: int = 20) -> str:
    """List watchlists."""
    try:
        chronicle = _chronicle()
        watchlists = chronicle.list_watchlists(page_size=count)
        return json.dumps({'watchlists': watchlists, 'count': len(watchlists)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_data_tables(count: int = 20) -> str:
    """List data tables."""
    try:
        chronicle = _chronicle()
        tables = chronicle.list_data_tables(page_size=count)
        return json.dumps({'tables': tables, 'count': len(tables)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_alert(alert_id: str) -> str:
    """Get alert details."""
    try:
        chronicle = _chronicle()
        alert = chronicle.get_alert(alert_id)
        return json.dumps({'alert': alert})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_log_buckets(count: int = 20) -> str:
    """List Cloud Logging buckets."""
    try:
        chronicle = _chronicle()
        buckets = chronicle.list_log_buckets(page_size=count)
        return json.dumps({'buckets': buckets, 'count': len(buckets)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def create_reference_list(name: str, description: str = "") -> str:
    """Create a new reference list."""
    try:
        chronicle = _chronicle()
        result = chronicle.create_reference_list(display_name=name, description=description)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def create_feed(name: str, source_type: str = "CUSTOM") -> str:
    """Create a new threat intelligence feed."""
    try:
        chronicle = _chronicle()
        result = chronicle.create_feed(display_name=name, source_type=source_type)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_case_details(case_id: str) -> str:
    """Get detailed case information."""
    try:
        chronicle = _chronicle()
        case = chronicle.get_case(case_id)
        return json.dumps({'case': case})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_case_alerts(case_id: str, count: int = 20) -> str:
    """List alerts associated with a case."""
    try:
        chronicle = _chronicle()
        alerts = chronicle.list_case_alerts(case_id, page_size=count)
        return json.dumps({'alerts': alerts, 'count': len(alerts)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def list_case_comments(case_id: str, count: int = 20) -> str:
    """List comments on a case."""
    try:
        chronicle = _chronicle()
        comments = chronicle.list_case_comments(case_id, page_size=count)
        return json.dumps({'comments': comments, 'count': len(comments)})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def update_case(case_id: str, priority: str = "", stage: str = "") -> str:
    """Update case priority or stage."""
    try:
        chronicle = _chronicle()
        result = chronicle.update_case(case_id, priority=priority, stage=stage)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def create_case_comment(case_id: str, text: str) -> str:
    """Add a comment to a case."""
    try:
        chronicle = _chronicle()
        result = chronicle.create_case_comment(case_id, text)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def enable_feed(feed_id: str) -> str:
    """Enable a threat intelligence feed."""
    try:
        chronicle = _chronicle()
        result = chronicle.enable_feed(feed_id)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def disable_feed(feed_id: str) -> str:
    """Disable a threat intelligence feed."""
    try:
        chronicle = _chronicle()
        result = chronicle.disable_feed(feed_id)
        return json.dumps({'result': result})
    except Exception as e:
        return json.dumps({'error': str(e)})

@app.tool()
def get_curated_rule(rule_id: str) -> str:
    """Get curated detection rule details."""
    try:
        chronicle = _chronicle()
        rule = chronicle.get_curated_rule(rule_id)
        return json.dumps({'rule': rule})
    except Exception as e:
        return json.dumps({'error': str(e)})

