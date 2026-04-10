#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Google-Native MCP Server (TypeScript Edition) — Cloud Run Deployment
# ═══════════════════════════════════════════════════════════════
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - A GCP project with billing enabled
#
# This script:
#   1. Creates the service account with least-privilege IAM roles
#   2. Enables all required APIs for 100+ tools
#   3. Builds the Docker container via Cloud Build (Node/TS)
#   4. Deploys to Cloud Run with Workload Identity
#   5. Outputs the service URL
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── CONFIGURATION (EDIT THESE) ───────────────────────────────

PROJECT_ID="${GCP_PROJECT_ID:-your-project-id}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="mcp-boss-ts"
SA_NAME="native-mcp-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
IMAGE_URL="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

# SecOps instance details
SECOPS_PROJECT_ID="${PROJECT_ID}"
SECOPS_CUSTOMER_ID="${SECOPS_CUSTOMER_ID:-your-customer-id}"
SECOPS_REGION="${SECOPS_REGION:-us}"

# ─── COLOR OUTPUT ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

# ─── PREFLIGHT CHECKS ────────────────────────────────────────

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  Google-Native MCP Server (TypeScript) — Deployment"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

log "Project: ${PROJECT_ID}"
log "Region:  ${REGION}"
log "Service: ${SERVICE_NAME}"
echo ""

gcloud projects describe "${PROJECT_ID}" > /dev/null 2>&1 || \
    err "Cannot access project ${PROJECT_ID}. Run: gcloud auth login && gcloud config set project ${PROJECT_ID}"

# ─── STEP 1: ENABLE REQUIRED APIS ────────────────────────────

log "Enabling required GCP APIs for 100+ tools..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    secretmanager.googleapis.com \
    securitycenter.googleapis.com \
    logging.googleapis.com \
    aiplatform.googleapis.com \
    chronicle.googleapis.com \
    cloudbilling.googleapis.com \
    monitoring.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    --project="${PROJECT_ID}" \
    --quiet

# ─── STEP 2: CREATE SERVICE ACCOUNT ──────────────────────────

if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    log "Service account ${SA_NAME} already exists."
else
    log "Creating service account: ${SA_NAME}"
    gcloud iam service-accounts create "${SA_NAME}" \
        --display-name="MCP Server Service Account" \
        --project="${PROJECT_ID}"
fi

# ─── STEP 3: BIND IAM ROLES ──────────────────────────────────

log "Binding IAM roles (least privilege)..."

ROLES=(
    "roles/chronicle.viewer"
    "roles/securitycenter.findingsViewer"
    "roles/logging.viewer"
    "roles/aiplatform.user"
    "roles/billing.viewer"
    "roles/monitoring.viewer"
    "roles/resourcemanager.organizationViewer"
    "roles/iam.securityReviewer"
)

for ROLE in "${ROLES[@]}"; do
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="${ROLE}" \
        --quiet > /dev/null 2>&1
    log "  Bound: ${ROLE}"
done

# ─── STEP 4: GTI API KEY (SECRET MANAGER) ────────────────────

if gcloud secrets describe "gti-api-key" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    log "Secret 'gti-api-key' already exists in Secret Manager."
else
    warn "GTI API key not found in Secret Manager."
    echo ""
    read -sp "    Enter your VirusTotal / GTI API key (or press Enter to skip): " GTI_KEY
    echo ""
    if [ -n "${GTI_KEY}" ]; then
        echo -n "${GTI_KEY}" | gcloud secrets create "gti-api-key" \
            --data-file=- \
            --project="${PROJECT_ID}" \
            --replication-policy="automatic"
        gcloud secrets add-iam-policy-binding "gti-api-key" \
            --member="serviceAccount:${SA_EMAIL}" \
            --role="roles/secretmanager.secretAccessor" \
            --project="${PROJECT_ID}" \
            --quiet > /dev/null 2>&1
        log "GTI API key stored in Secret Manager."
    else
        warn "Skipping GTI setup. The enrich_indicator tool will be unavailable."
    fi
fi

# ─── STEP 5: BUILD CONTAINER ─────────────────────────────────

log "Building Docker container via Cloud Build (Node/TS environment)..."
gcloud builds submit \
    --tag "${IMAGE_URL}" \
    --project="${PROJECT_ID}" \
    --quiet

# ─── STEP 6: DEPLOY TO CLOUD RUN ─────────────────────────────

log "Deploying to Cloud Run..."

DEPLOY_CMD="gcloud run deploy ${SERVICE_NAME} \
    --image ${IMAGE_URL} \
    --region ${REGION} \
    --service-account ${SA_EMAIL} \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 120 \
    --set-env-vars=SECOPS_PROJECT_ID=${SECOPS_PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=${SECOPS_REGION} \
    --project=${PROJECT_ID} \
    --quiet"

if gcloud secrets describe "gti-api-key" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    DEPLOY_CMD="${DEPLOY_CMD} --set-secrets=GTI_API_KEY=gti-api-key:latest"
fi

eval "${DEPLOY_CMD}"

# ─── STEP 7: GET SERVICE URL ─────────────────────────────────

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --format="value(status.url)")

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Deployment Complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Service URL:  ${GREEN}${SERVICE_URL}${NC}"
echo -e "  Health Check: ${GREEN}${SERVICE_URL}/health${NC}"
echo -e "  SSE Endpoint: ${GREEN}${SERVICE_URL}/sse${NC}"
echo -e "  Web Chat UI:  ${GREEN}${SERVICE_URL}/${NC}"
echo ""
echo -e "  ${YELLOW}Note: --no-allow-unauthenticated is set.${NC}"
echo -e "  ${YELLOW}Callers need roles/run.invoker or a valid ID token.${NC}"
echo ""
echo -e "  Test health check:"
echo -e "  ${CYAN}curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" ${SERVICE_URL}/health${NC}"
echo ""
