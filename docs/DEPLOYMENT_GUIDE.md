# Google-Native Autonomous MCP Server — Deployment Guide

## 🎯 What This Is

A production-ready Model Context Protocol (MCP) server that gives any LLM (Vertex AI, Claude, GPT) autonomous access to your entire Google Cloud Security stack through a single endpoint:

| Tool | API | What It Does |
|---|---|---|
| `get_scc_findings` | Security Command Center | Query ACTIVE vulnerabilities and misconfigurations |
| `query_cloud_logging` | Cloud Logging | Search IAM changes, compute creation, storage access |
| `search_secops_udm` | Google SecOps (Chronicle) | Execute UDM searches and YARA-L queries |
| `list_secops_detections` | Google SecOps (Chronicle) | List recent YARA-L detection alerts with outcomes |
| `enrich_indicator` | Google Threat Intel / VT | Enrich IPs, domains, URLs, and file hashes |
| `vertex_ai_investigate` | Vertex AI (Gemini) | AI-powered threat analysis and report generation |

**Architecture:** Single Docker container → Cloud Run (serverless) → Workload Identity (zero secrets).

---

## 📋 Prerequisites

### Required
- [ ] GCP project with billing enabled
- [ ] `gcloud` CLI installed and authenticated (`gcloud auth login`)
- [ ] Google SecOps (Chronicle) instance active
- [ ] The following APIs enabled (the deploy script handles this):
  - Cloud Run
  - Cloud Build
  - Secret Manager
  - Security Command Center
  - Cloud Logging
  - Vertex AI
  - Chronicle

### Optional
- [ ] VirusTotal / GTI API key (for `enrich_indicator` tool)
- [ ] Docker installed (for local testing only — not needed for Cloud Run deployment)

---

## 🚀 Quick Start (5 Minutes)

### Option A: Automated Deployment (Recommended)

```bash
# 1. Clone or navigate to the bundle
cd /path/to/Google_Native_MCP_Server

# 2. Set your project ID
export GCP_PROJECT_ID="your-project-id"
export SECOPS_CUSTOMER_ID="your-secops-customer-id"

# 3. Run the deployment script
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Enable all required GCP APIs
2. Create a service account with least-privilege IAM roles
3. Prompt for your GTI/VT API key (optional) and store it in Secret Manager
4. Build the Docker container via Cloud Build
5. Deploy to Cloud Run with Workload Identity
6. Output the service URL

### Option B: Manual Deployment (Step by Step)

Follow the detailed instructions below.

---

## 📖 Detailed Deployment Instructions

### Step 1: Configure Your Environment

```bash
# Set variables (edit these)
export PROJECT_ID="your-project-id"
export REGION="us-central1"
export SERVICE_NAME="mcp-boss-ts"
export SA_NAME="mcp-boss-sa"
export SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Your SecOps instance details
# Find these in: SecOps Console → Settings → SIEM Settings
export SECOPS_PROJECT_ID="${PROJECT_ID}"
export SECOPS_CUSTOMER_ID="your-customer-id"    # UUID format
export SECOPS_REGION="us"                         # us, europe, or asia
```

**Where to find your SecOps Customer ID:**
1. Open Google SecOps Console
2. Navigate to **Settings → SIEM Settings**
3. The Customer ID is displayed as a UUID (e.g., `1d49deb2eaa7427ca1d1e78ccaa91c10`)

### Step 2: Enable Required APIs

```bash
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    cloudbilling.googleapis.com \
    monitoring.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    secretmanager.googleapis.com \
    securitycenter.googleapis.com \
    logging.googleapis.com \
    aiplatform.googleapis.com \
    chronicle.googleapis.com \
    --project="${PROJECT_ID}"
```

### Step 3: Create the Service Account

```bash
# Create the service account
gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="MCP Server Service Account" \
    --project="${PROJECT_ID}"

# Bind least-privilege IAM roles
for ROLE in \
    roles/chronicle.viewer \
    roles/securitycenter.findingsViewer \
    roles/logging.viewer \
    roles/aiplatform.user \
    roles/billing.viewer \
    roles/monitoring.viewer \
    roles/resourcemanager.organizationViewer \
    roles/iam.securityReviewer; do
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="${ROLE}" \
        --quiet
done
```

**IAM Role Reference:**

| Role | Access Level | Required For |
|---|---|---|
| `roles/chronicle.viewer` | Read-only SecOps | `search_secops_udm`, `list_secops_detections` |
| `roles/securitycenter.findingsViewer` | Read-only SCC | `get_scc_findings` |
| `roles/logging.viewer` | Read-only Cloud Logging | `query_cloud_logging` |
| `roles/aiplatform.user` | Invoke Vertex AI | `vertex_ai_investigate` |

**If you need write access** (e.g., creating YARA-L rules, triggering playbooks):
- Replace `chronicle.viewer` with `roles/chronicle.editor` or `roles/chronicle.admin`
- This is NOT recommended for initial deployment

### Step 4: Configure GTI / VirusTotal API Key

```bash
# Store the API key in Secret Manager
echo -n "YOUR_VT_API_KEY" | gcloud secrets create "gti-api-key" \
    --data-file=- \
    --project="${PROJECT_ID}" \
    --replication-policy="automatic"

# Grant the service account access to the secret
gcloud secrets add-iam-policy-binding "gti-api-key" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}"
```

**Skipping GTI:** If you don't have a VT/GTI API key, skip this step. The `enrich_indicator` tool will return a helpful error message directing users to configure the key.

### Step 5: Build the Container

```bash
# Build via Cloud Build (no local Docker needed)
gcloud builds submit \
    --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest" \
    --project="${PROJECT_ID}"
```

**Expected output:**
```
Creating temporary tarball archive...
Uploading tarball...
Created [https://cloudbuild.googleapis.com/v1/projects/...]
BUILD SUCCESSFUL
```

### Step 6: Deploy to Cloud Run

```bash
gcloud run deploy "${SERVICE_NAME}" \
    --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest" \
    --region "${REGION}" \
    --service-account "${SA_EMAIL}" \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 120 \
    --set-env-vars="SECOPS_PROJECT_ID=${SECOPS_PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=${SECOPS_REGION}" \
    --set-secrets="GTI_API_KEY=gti-api-key:latest" \
    --project="${PROJECT_ID}"
```

**Configuration decisions:**

| Parameter | Value | Rationale |
|---|---|---|
| `--no-allow-unauthenticated` | Required | MCP server should never be public. Callers must present a valid ID token. |
| `--memory 512Mi` | Default | Sufficient for API proxying. Increase to 1Gi if Vertex AI responses are large. |
| `--min-instances 0` | Cost optimization | Scales to zero when idle. First request has ~2s cold start. |
| `--max-instances 10` | Safety cap | Prevents runaway scaling during incident surges. |
| `--timeout 120` | 2 minutes | Vertex AI and SecOps searches can take up to 60s. |

### Step 7: Verify the Deployment

```bash
# Get the service URL
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --region="${REGION}" --project="${PROJECT_ID}" \
    --format="value(status.url)")

# Test the health check
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
    "${SERVICE_URL}/health"
```

**Expected response:**
```json
{
    "status": "healthy",
    "server": "mcp-boss-ts",
    "project": "your-project-id",
    "region": "us",
    "gti_configured": true,
    "adc_status": "valid"
}
```

---

## 🖥️ Local Development & Testing

For development and testing without deploying to Cloud Run:

```bash
# 1. Authenticate locally
gcloud auth application-default login

# 2. Set environment variables
export SECOPS_PROJECT_ID="your-project-id"
export SECOPS_CUSTOMER_ID="your-customer-id"
export SECOPS_REGION="us"
export GTI_API_KEY="your-vt-api-key"  # optional

# 3. Install dependencies
pnpm install

# 4. Run the server
pnpm run dev

# 5. Test health check
curl http://localhost:8080/health
```

Or use the included script:
```bash
chmod +x test_local.sh
./test_local.sh
```

---

## 🔌 Connecting an MCP Client

### Claude Desktop / Claude Code

Add to your MCP client configuration:

```json
{
    "mcpServers": {
        "google-security": {
            "url": "https://your-service-url.run.app/sse",
            "headers": {
                "Authorization": "Bearer YOUR_ID_TOKEN"
            }
        }
    }
}
```

**Getting an ID token for the client:**
```bash
gcloud auth print-identity-token --audiences="https://your-service-url.run.app"
```

### Vertex AI (Gemini) as the Client

To use Vertex AI as the autonomous investigation engine driving the MCP tools, configure the MCP client in your Vertex AI application to point at the Cloud Run SSE endpoint. The Vertex AI `vertex_ai_investigate` tool within the MCP server itself can also be chained — Tool 6 can analyze the output of Tools 1-5.

### Custom Python Client

```python
import requests

SERVICE_URL = "https://your-service-url.run.app"
TOKEN = "your-id-token"

# Connect to the SSE endpoint
headers = {"Authorization": f"Bearer {TOKEN}"}

# Call a tool via the MCP protocol
response = requests.post(
    f"{SERVICE_URL}/messages",
    headers=headers,
    json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "get_scc_findings",
            "arguments": {"project_id": "your-project-id"}
        },
        "id": 1
    }
)
print(response.json())
```

---

## 🔒 Security Hardening (Production)

### 1. VPC Service Controls

Restrict which networks can reach the MCP server:

```bash
# Create a VPC connector for Cloud Run
gcloud compute networks vpc-access connectors create mcp-connector \
    --region="${REGION}" \
    --network=default \
    --range=10.8.0.0/28

# Update Cloud Run to use internal-only ingress
gcloud run services update "${SERVICE_NAME}" \
    --region="${REGION}" \
    --ingress=internal-and-cloud-load-balancing \
    --vpc-connector=mcp-connector
```

### 2. Cloud Armor (WAF)

If exposed via a load balancer, add Cloud Armor for rate limiting:

```bash
gcloud compute security-policies create mcp-policy \
    --description="Rate limit MCP server"

gcloud compute security-policies rules create 1000 \
    --security-policy=mcp-policy \
    --expression="true" \
    --action=rate-based-ban \
    --rate-limit-threshold-count=100 \
    --rate-limit-threshold-interval-sec=60 \
    --ban-duration-sec=300
```

### 3. Audit Logging

All Cloud Run invocations are automatically logged in Cloud Audit Logs. Create an alert for anomalous usage:

```bash
# Alert if the MCP server is called more than 500 times in 5 minutes
gcloud alpha monitoring policies create \
    --display-name="MCP Server Anomalous Usage" \
    --condition-display-name="High request rate" \
    --condition-filter='resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/request_count"' \
    --condition-threshold-value=500 \
    --condition-threshold-duration=300s
```

---

## 🔧 Troubleshooting

### Common Errors

| Error | Cause | Fix |
|---|---|---|
| `401 Unauthenticated` on health check | Missing or invalid ID token | `gcloud auth print-identity-token --audiences="SERVICE_URL"` |
| `403 Permission Denied` on SCC | Missing IAM role | Bind `roles/securitycenter.findingsViewer` to the SA |
| `403 Permission Denied` on SecOps | Missing Chronicle role | Bind `roles/chronicle.viewer` to the SA |
| `ADC token rejected` | Workload Identity not configured | Verify SA is attached to Cloud Run revision |
| `GTI_API_KEY not configured` | Secret not mounted | `--set-secrets="GTI_API_KEY=gti-api-key:latest"` |
| `Timeout` on SecOps search | Query too broad or time range too large | Narrow the query and reduce `hours_back` |
| `503 Service Unavailable` | Cold start or resource exhaustion | Increase `--min-instances 1` to eliminate cold starts |
| Container fails to start | Port mismatch | Ensure Dockerfile uses port 8080 and `$PORT` env var |

### Checking Logs

```bash
# Stream Cloud Run logs in real-time
gcloud run services logs tail "${SERVICE_NAME}" \
    --region="${REGION}" --project="${PROJECT_ID}"

# Search for specific errors
gcloud logging read \
    'resource.type="cloud_run_revision" AND severity>=ERROR' \
    --project="${PROJECT_ID}" \
    --limit=20 \
    --format=json
```

### Updating the Server

```bash
# Rebuild and redeploy (zero-downtime)
gcloud builds submit --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"
gcloud run deploy "${SERVICE_NAME}" \
    --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest" \
    --region "${REGION}"
```

---

## 📁 Bundle File Reference

```
Google_Native_MCP_Server/
├── main.py                  # The MCP server (6 tools, health check, SSE transport)
├── requirements.txt         # Python dependencies
├── Dockerfile               # Production container (non-root, Cloud Run ready)
├── deploy.sh                # One-command automated deployment
├── test_local.sh            # Local development runner
└── docs/
    └── DEPLOYMENT_GUIDE.md  # This file
```

---

## 🎯 The Autonomous Kill Chain (Example)

Once deployed, an LLM client (Vertex AI, Claude, etc.) can execute a fully autonomous investigation:

```
Step 1: "Check SCC for critical findings in project prod-backend"
        → get_scc_findings("prod-backend", severity="CRITICAL")
        → Returns: GKE node with CVE-2024-XXXX, actively exploitable

Step 2: "Who modified IAM on that node recently?"
        → query_cloud_logging("prod-backend", 'protoPayload.methodName="SetIamPolicy"')
        → Returns: Service account dev-sa@prod.iam.gsa.com granted roles/editor 2 hours ago

Step 3: "Search SecOps for process launches from that node"
        → search_secops_udm('metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "gke-node-abc"')
        → Returns: curl executed outbound to 198.51.100.42

Step 4: "Enrich that IP"
        → enrich_indicator("198.51.100.42")
        → Returns: 15/90 VT engines flagged malicious, ASN: BULLETPROOF-HOSTING

Step 5: "Generate an incident report"
        → vertex_ai_investigate(context=<all previous results>, task="Generate incident report")
        → Returns: Structured report proving active exploitation with MITRE mapping
```

**Total time:** < 30 seconds. Zero human intervention. Full forensic trail.
