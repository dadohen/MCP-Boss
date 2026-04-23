#!/bin/bash
# One-command build + deploy + push for MCP Boss.
# Project-agnostic — reads SECOPS_PROJECT_ID from env.
set -euo pipefail

: "${SECOPS_PROJECT_ID:?Set SECOPS_PROJECT_ID (target GCP project ID)}"
: "${SECOPS_CUSTOMER_ID:?Set SECOPS_CUSTOMER_ID (Chronicle customer UUID)}"
SECOPS_REGION="${SECOPS_REGION:-us}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-mcp-boss}"
REPO="${REPO:-mcp-boss}"
IMAGE="${REGION}-docker.pkg.dev/${SECOPS_PROJECT_ID}/${REPO}/${SERVICE}:latest"

echo "Building image: $IMAGE"
gcloud builds submit --tag "$IMAGE" --project "$SECOPS_PROJECT_ID" --quiet

echo "Deploying $SERVICE to Cloud Run in $REGION..."
# Auto-compute the version string: 4.0.<patches> where <patches> is the
# number of commits since 06da7d7 (the 4.0.0 bump). Appends -dirty if the
# working tree has uncommitted changes, so a local hot-deploy is obvious
# in /health.
BASE_COMMIT="06da7d7"
if git rev-parse "$BASE_COMMIT" >/dev/null 2>&1; then
  PATCH=$(git rev-list --count "${BASE_COMMIT}..HEAD" 2>/dev/null || echo 0)
else
  PATCH=$(git rev-list --count HEAD 2>/dev/null || echo 0)
fi
DIRTY=""
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then DIRTY="-dirty"; fi
VERSION="4.0.${PATCH}${DIRTY}"
echo "Setting VERSION=${VERSION}"

gcloud run deploy "$SERVICE" \
    --image "$IMAGE" \
    --region "$REGION" \
    --project "$SECOPS_PROJECT_ID" \
    --allow-unauthenticated \
    --memory 512Mi \
    --timeout 120 \
    --update-env-vars "SECOPS_PROJECT_ID=${SECOPS_PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=${SECOPS_REGION},VERSION=${VERSION}" \
    --quiet

if [ -d .git ] && [ "${GIT_PUSH:-1}" = "1" ]; then
  echo "Committing and pushing..."
  git add -A
  git commit -m "Deploy: $(date -u +%Y-%m-%dT%H:%M:%SZ) — $(grep -c '@app_mcp.tool' main.py) tools" 2>/dev/null || echo "Nothing to commit"
  git push 2>/dev/null || echo "Push skipped — check git auth"
fi

URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$SECOPS_PROJECT_ID" --format='value(status.url)')
echo "Deployed: $URL"
echo ""
echo "Health check:"
curl -sS "${URL}/health" | python3 -m json.tool || echo "(health endpoint did not return JSON)"
