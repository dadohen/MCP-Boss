#!/bin/bash
# One-command: build, deploy to Cloud Run, push to GitHub
set -e

PROJECT_ID="tito-436719"
CUSTOMER_ID="1d49deb2eaa7427ca1d1e78ccaa91c10"
REGION="us"
IMAGE="us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest"

echo "🔨 Building..."
gcloud builds submit --tag ${IMAGE} --quiet

echo "🚀 Deploying..."
gcloud run deploy google-native-mcp \
    --image ${IMAGE} \
    --region us-central1 \
    --allow-unauthenticated \
    --memory 512Mi \
    --timeout 120 \
    --set-env-vars="SECOPS_PROJECT_ID=${PROJECT_ID},SECOPS_CUSTOMER_ID=${CUSTOMER_ID},SECOPS_REGION=${REGION}" \
    --quiet

echo "📦 Pushing to GitHub..."
git add -A
git commit -m "Update: $(date +%Y-%m-%d) — $(grep -c '@app_mcp.tool' main.py) tools" 2>/dev/null || echo "Nothing to commit"
git push 2>/dev/null || echo "Push failed — check git auth"

echo "✅ Done. Health check:"
curl -s https://google-native-mcp-672020644906.us-central1.run.app/health | python3 -m json.tool
