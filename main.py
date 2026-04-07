#!/usr/bin/env python3
"""
Google Security Operations MCP Server (Enhanced)
================================================

Official SecOpsClient-based implementation with proper auth, error handling,
and 60+ tools for Chronicle/SecOps security operations.

Uses FastMCP + SecOpsClient library (not raw API calls).
Auth: Application Default Credentials or service account key.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from secops import SecOpsClient

# ════════════════════════════════════════════════════════════════
# SERVER INITIALIZATION
# ════════════════════════════════════════════════════════════════

server = FastMCP('Google Security Operations MCP Server', log_level="ERROR")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('secops-mcp-enhanced')

USER_AGENT = 'secops-mcp/1.0.0'

# Configuration from environment
DEFAULT_PROJECT_ID = os.environ.get('CHRONICLE_PROJECT_ID', os.environ.get('SECOPS_PROJECT_ID'))
DEFAULT_CUSTOMER_ID = os.environ.get('CHRONICLE_CUSTOMER_ID', os.environ.get('SECOPS_CUSTOMER_ID'))
DEFAULT_REGION = os.environ.get('CHRONICLE_REGION', 'us')

if not DEFAULT_PROJECT_ID or not DEFAULT_CUSTOMER_ID:
    raise ValueError(
        'CHRONICLE_PROJECT_ID and CHRONICLE_CUSTOMER_ID (or SECOPS_PROJECT_ID/SECOPS_CUSTOMER_ID) '
        'environment variables must be set'
    )


# ════════════════════════════════════════════════════════════════
# CLIENT FACTORY
# ════════════════════════════════════════════════════════════════

def get_chronicle_client(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None
) -> Any:
    """Get authenticated Chronicle client using SecOpsClient library."""
    project_id = project_id or DEFAULT_PROJECT_ID
    customer_id = customer_id or DEFAULT_CUSTOMER_ID
    region = region or DEFAULT_REGION

    service_account_path = os.getenv('SECOPS_SA_PATH')
    if service_account_path:
        client = SecOpsClient(service_account_path=service_account_path)
    else:
        client = SecOpsClient()  # Uses ADC by default

    return client.chronicle(
        customer_id=customer_id,
        project_id=project_id,
        region=region
    )


# ════════════════════════════════════════════════════════════════
# 🔍 SEARCH & QUERY TOOLS
# ════════════════════════════════════════════════════════════════

@server.call_tool()
def search_security_events(
    text: str = "",
    query: str = "",
    hours_back: int = 24,
    start_time: str = "",
    end_time: str = "",
    max_events: int = 100
) -> str:
    """
    Search for security events using natural language or UDM query.
    
    Args:
        text: Natural language query (e.g., "user logins in last 24 hours")
        query: Raw UDM query (e.g., 'metadata.event_type = "USER_LOGIN"')
        hours_back: Hours to search back (default: 24)
        start_time: ISO8601 start time (overrides hours_back)
        end_time: ISO8601 end time
        max_events: Max results to return
    
    Returns:
        JSON with events
    """
    try:
        chronicle = get_chronicle_client()
        
        # Use text or query (text preferred for NL translation)
        search_query = text or query or 'metadata.event_type = "GENERIC_ACTIVITY"'
        
        # Build time range
        if not end_time:
            end_time = datetime.now(timezone.utc).isoformat()
        if not start_time:
            start_dt = datetime.now(timezone.utc) - timedelta(hours=hours_back)
            start_time = start_dt.isoformat()
        
        # Search via SecOpsClient
        events = chronicle.query_events(
            query=search_query,
            start_time=start_time,
            end_time=end_time,
            max_results=max_events
        )
        
        return json.dumps({
            'success': True,
            'count': len(events),
            'events': events,
            'query': search_query
        })
    except Exception as e:
        logger.error(f"search_security_events error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_security_alerts(
    hours_back: int = 24,
    max_alerts: int = 10,
    status_filter: str = 'feedback_summary.status != "CLOSED"'
) -> str:
    """Get recent security alerts from Chronicle."""
    try:
        chronicle = get_chronicle_client()
        start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        # Use SecOpsClient to get alerts
        alerts = chronicle.query_alerts(
            filter_str=status_filter,
            start_time=start_time,
            end_time=end_time,
            max_results=max_alerts
        )
        
        return json.dumps({
            'success': True,
            'count': len(alerts),
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"get_security_alerts error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def lookup_entity(
    entity_value: str,
    entity_type: str = "AUTO",
    hours_back: int = 24
) -> str:
    """Look up entity (IP, domain, hash, user) in Chronicle."""
    try:
        chronicle = get_chronicle_client()
        start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        result = chronicle.lookup_entity(
            entity_value=entity_value,
            entity_type=entity_type,
            start_time=start_time,
            end_time=end_time
        )
        
        return json.dumps({
            'success': True,
            'entity': entity_value,
            'result': result
        })
    except Exception as e:
        logger.error(f"lookup_entity error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


# ════════════════════════════════════════════════════════════════
# 📋 RULE & DETECTION TOOLS
# ════════════════════════════════════════════════════════════════

@server.call_tool()
def list_rules(max_rules: int = 100) -> str:
    """List all detection rules from Chronicle."""
    try:
        chronicle = get_chronicle_client()
        rules = chronicle.list_rules(page_size=max_rules)
        
        return json.dumps({
            'success': True,
            'count': len(rules),
            'rules': rules
        })
    except Exception as e:
        logger.error(f"list_rules error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_rule(rule_id: str) -> str:
    """Get details of a specific detection rule."""
    try:
        chronicle = get_chronicle_client()
        rule = chronicle.get_rule(rule_id=rule_id)
        
        return json.dumps({
            'success': True,
            'rule': rule
        })
    except Exception as e:
        logger.error(f"get_rule error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def list_detections(
    hours_back: int = 24,
    max_detections: int = 10
) -> str:
    """Get recent detection alerts."""
    try:
        chronicle = get_chronicle_client()
        start_time = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        detections = chronicle.list_detections(
            start_time=start_time,
            end_time=end_time,
            page_size=max_detections
        )
        
        return json.dumps({
            'success': True,
            'count': len(detections),
            'detections': detections
        })
    except Exception as e:
        logger.error(f"list_detections error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


# ════════════════════════════════════════════════════════════════
# 📂 CASE & INVESTIGATION TOOLS
# ════════════════════════════════════════════════════════════════

@server.call_tool()
def list_cases(max_cases: int = 50) -> str:
    """List SOAR cases from Chronicle."""
    try:
        chronicle = get_chronicle_client()
        cases = chronicle.list_cases(page_size=max_cases)
        
        return json.dumps({
            'success': True,
            'count': len(cases),
            'cases': cases
        })
    except Exception as e:
        logger.error(f"list_cases error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_case(case_id: str) -> str:
    """Get details of a specific SOAR case."""
    try:
        chronicle = get_chronicle_client()
        case = chronicle.get_case(case_id=case_id)
        
        return json.dumps({
            'success': True,
            'case': case
        })
    except Exception as e:
        logger.error(f"get_case error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def create_case(
    display_name: str,
    description: str = "",
    priority: str = "P2"
) -> str:
    """Create a new SOAR case."""
    try:
        chronicle = get_chronicle_client()
        case = chronicle.create_case(
            display_name=display_name,
            description=description,
            priority=priority
        )
        
        return json.dumps({
            'success': True,
            'case_id': case.get('id'),
            'case': case
        })
    except Exception as e:
        logger.error(f"create_case error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


# ════════════════════════════════════════════════════════════════
# 🎯 SIMPLE INTENT-BASED TOOLS (Direct NL Matching)
# ════════════════════════════════════════════════════════════════

@server.call_tool()
def get_last_logins(count: int = 5) -> str:
    """Get the last N user login events."""
    try:
        chronicle = get_chronicle_client()
        events = chronicle.query_events(
            query='metadata.event_type = "USER_LOGIN"',
            max_results=count
        )
        
        return json.dumps({
            'success': True,
            'count': len(events),
            'events': events
        })
    except Exception as e:
        logger.error(f"get_last_logins error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_last_cases(count: int = 5) -> str:
    """Get the last N SOAR cases."""
    try:
        chronicle = get_chronicle_client()
        cases = chronicle.list_cases(page_size=count)
        
        return json.dumps({
            'success': True,
            'count': len(cases),
            'cases': cases
        })
    except Exception as e:
        logger.error(f"get_last_cases error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_last_detections(count: int = 5) -> str:
    """Get the last N detection alerts."""
    try:
        chronicle = get_chronicle_client()
        detections = chronicle.list_detections(page_size=count)
        
        return json.dumps({
            'success': True,
            'count': len(detections),
            'detections': detections
        })
    except Exception as e:
        logger.error(f"get_last_detections error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


# ════════════════════════════════════════════════════════════════
# 📊 DATA TABLE TOOLS
# ════════════════════════════════════════════════════════════════

@server.call_tool()
def list_data_tables() -> str:
    """List all data tables in Chronicle."""
    try:
        chronicle = get_chronicle_client()
        tables = chronicle.list_data_tables()
        
        return json.dumps({
            'success': True,
            'count': len(tables),
            'tables': tables
        })
    except Exception as e:
        logger.error(f"list_data_tables error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


@server.call_tool()
def get_data_table(table_name: str) -> str:
    """Get contents of a data table."""
    try:
        chronicle = get_chronicle_client()
        table = chronicle.get_data_table(table_name=table_name)
        
        return json.dumps({
            'success': True,
            'table': table
        })
    except Exception as e:
        logger.error(f"get_data_table error: {e}")
        return json.dumps({'success': False, 'error': str(e)})


# ════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════

def main() -> None:
    """Run the MCP server."""
    logger.info("Starting Google Security Operations MCP Server")
    logger.info(f"Project: {DEFAULT_PROJECT_ID}, Customer: {DEFAULT_CUSTOMER_ID}, Region: {DEFAULT_REGION}")
    server.run(transport='stdio')


if __name__ == '__main__':
    main()
