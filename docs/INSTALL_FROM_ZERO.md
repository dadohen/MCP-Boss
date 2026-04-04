# 🚀 From GitHub to Cloud Run — The Complete Install Guide

## What You're Building

You're taking code from the internet (GitHub), putting it in a box (Docker container), and running that box on Google's servers (Cloud Run). When you're done, you get a URL. Any AI that knows how to speak MCP can use that URL to search your SIEM, enrich threat intel, isolate endpoints, purge phishing emails, and more.

**Total time:** 20–30 minutes, start to finish.

**Total cost:** Free while idle. ~$5/month with moderate use.

---

## What You Need Before Starting

You need 3 things. If you're missing any of them, follow the instructions below to get them.

### Thing 1: A Google Cloud Account

This is how you pay for Google Cloud services (like Cloud Run).

**Already have one?** Go to https://console.cloud.google.com — if you can log in, you're good. Skip to Thing 2.

**Don't have one?** Here's how to create it:

1. Go to **https://cloud.google.com** in your browser
2. Click **"Get started for free"** (top right)
3. Sign in with your Google account (the same one you use for Gmail)
4. Google gives you **$300 in free credits** for 90 days — more than enough
5. You need to add a credit card, but you **won't be charged** unless you manually upgrade to a paid account
6. Fill out the billing info and click **"Start Free"**

You now have a Google Cloud account.

### Thing 2: A Google Cloud Project

A "project" is like a folder that holds all your cloud resources. Every API, every server, every secret lives inside a project.

**Create one:**

1. Go to **https://console.cloud.google.com**
2. At the very top of the page, you'll see a dropdown next to "Google Cloud" — it might say "Select a project" or show an existing project name
3. Click that dropdown
4. Click **"NEW PROJECT"** (top right of the popup)
5. **Project name:** Type something like `secops-mcp` (lowercase, no spaces)
6. **Organization:** Leave as default (or pick yours if you see one)
7. Click **"CREATE"**
8. Wait 10 seconds. It'll say "Your new project is ready."
9. Click **"SELECT PROJECT"** to switch to it

**Write down your Project ID.** It's shown under the project name (looks like `secops-mcp` or `secops-mcp-123456`). You'll need this later.

### Thing 3: The `gcloud` Command Line Tool

This is the tool that lets you control Google Cloud from your terminal (instead of clicking around the website).

**Check if you already have it:**
```bash
gcloud version
```
If you see version numbers, skip to Step 1. If you see "command not found," install it:

**Mac:**
```bash
brew install google-cloud-sdk
```
Don't have `brew`? Go to https://brew.sh and follow the one-line install, then come back.

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates gnupg curl

curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg

echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list

sudo apt-get update
sudo apt-get install -y google-cloud-cli
```

**Windows:**
1. Go to **https://cloud.google.com/sdk/docs/install#windows**
2. Download the installer
3. Run it. Click Next through everything.
4. At the end, check "Run gcloud init" and click Finish

**Verify it works:**
```bash
gcloud version
```
You should see something like `Google Cloud SDK 470.0.0`. The exact version doesn't matter.

---

## Step 1: Log In to Google Cloud

Open your terminal and run:

```bash
gcloud auth login
```

**What happens:** Your web browser opens automatically. Sign in with the same Google account you used to create the Cloud account. Click **"Allow"** when Google asks for permissions.

Your terminal will say: `You are now logged in as [your-email@gmail.com]`

Now tell gcloud which project to use:

```bash
gcloud config set project YOUR_PROJECT_ID
```

**Replace `YOUR_PROJECT_ID`** with the Project ID you wrote down in Thing 2 (e.g., `secops-mcp`).

**Not sure what your Project ID is?** Run:
```bash
gcloud projects list
```
It shows all your projects. Copy the one you want and use it.

---

## Step 2: Download the Code

You need to get the MCP Server code from GitHub onto your computer. Pick the easiest option for you:

### Option A: Download as ZIP (No Git Required — Easiest)

1. Open your browser
2. Go to: **https://github.com/dnehoda-source/Google-Native-MCP-Server**
3. Look for the big green button that says **"<> Code"**
4. Click it
5. In the dropdown, click **"Download ZIP"**
6. Your browser downloads a file called `Google-Native-MCP-Server-main.zip`
7. Find it in your **Downloads** folder
8. **Unzip it:**
   - **Mac:** Double-click the ZIP file
   - **Windows:** Right-click → "Extract All"
   - **Linux:** `unzip Google-Native-MCP-Server-main.zip`
9. Open your terminal and go to the folder:

```bash
cd ~/Downloads/Google-Native-MCP-Server-main
```

### Option B: Use Git Clone

```bash
cd ~/Desktop
git clone https://github.com/dnehoda-source/Google-Native-MCP-Server.git
cd Google-Native-MCP-Server
```

**Don't have git?** Just use Option A. It's the same code.

---

## Step 3: Turn On the Google Cloud Services

Google Cloud has hundreds of services, but they're all turned off by default. Your MCP server needs 7 of them. Here's what each one does:

| Service | What It Is | Why Your Server Needs It |
|---|---|---|
| **Cloud Run** | Runs your server in the cloud | This is where your MCP server actually lives and runs |
| **Cloud Build** | Builds Docker containers in the cloud | Takes your code and packages it — you don't need Docker on your computer |
| **Secret Manager** | Stores passwords and API keys securely | Holds your VirusTotal API key so it's encrypted, not in plain text |
| **Security Command Center** | Google's vulnerability scanner | The `get_scc_findings` tool queries this to find misconfigurations |
| **Cloud Logging** | Stores audit logs for everything in your GCP project | The `query_cloud_logging` tool searches IAM changes, compute events, etc. |
| **Vertex AI** | Google's AI platform (Gemini) | The `vertex_ai_investigate` tool uses Gemini to analyze security findings |
| **Chronicle API** | Google SecOps (your SIEM) | The UDM search, detections, Data Tables, and rule management tools all use this |

Turn them all on with one command:

```bash
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    secretmanager.googleapis.com \
    securitycenter.googleapis.com \
    logging.googleapis.com \
    aiplatform.googleapis.com \
    chronicle.googleapis.com
```

**What happens:** Google turns on each service. You'll see "Operation finished successfully" for each one. Takes about 30 seconds total.

**If you see "PERMISSION_DENIED":** You're not a Project Owner or Editor. Either:
- Ask your GCP admin to grant you the **Editor** role on the project
- Or ask them to run this command for you

---

## Step 4: Create a Service Account

Your server needs an identity to talk to Google's APIs. In Google Cloud, that identity is called a "service account." Think of it as a username and password that belongs to the server, not to you.

### Create it:

```bash
gcloud iam service-accounts create native-mcp-sa \
    --display-name="MCP Server Service Account"
```

**If you see "already exists":** That's fine. It was created before. Keep going.

### Give it permissions:

Now we tell Google what this service account is allowed to do. We're giving it **read-only** access to your security tools — it can look at data but can't change anything.

```bash
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Permission to read SecOps data (UDM search, detections, rules)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/chronicle.viewer" --quiet

# Permission to read Security Command Center findings
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/securitycenter.findingsViewer" --quiet

# Permission to read Cloud Logging entries
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.viewer" --quiet

# Permission to use Vertex AI (Gemini)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/aiplatform.user" --quiet
```

**What each permission does:**

| Permission | English Translation |
|---|---|
| `chronicle.viewer` | "You can search the SIEM and read detections, but you can't create or delete rules" |
| `securitycenter.findingsViewer` | "You can see vulnerabilities, but you can't dismiss or modify them" |
| `logging.viewer` | "You can read audit logs, but you can't delete them" |
| `aiplatform.user` | "You can ask Gemini questions, but you can't deploy models" |

### Give Cloud Build permission to build and push containers:

When you build your container in Step 7, Google uses a special "Cloud Build service account" to do the work. This account needs permission to store the finished container image and write build logs. Without these, the build will succeed but then fail when trying to save the result.

First, find your project number (it's different from your project ID):

```bash
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
```

Now grant the Cloud Build service account the permissions it needs:

```bash
# Permission to store the built container image
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/storage.admin" --quiet

# Permission to push the container to the registry
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/artifactregistry.writer" --quiet

# Permission to write build logs
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/logging.logWriter" --quiet
```

**What each permission does:**

| Permission | English Translation |
|---|---|
| `storage.admin` | "Cloud Build can store and retrieve files in Cloud Storage (where your code gets uploaded before building)" |
| `artifactregistry.writer` | "Cloud Build can push the finished Docker container image to the container registry" |
| `logging.logWriter` | "Cloud Build can write its build logs so you can see what happened" |

**Why is this a separate step?** Google Cloud projects created through different methods (console, org admin, API) have different default permissions. Some projects grant these automatically, others don't. Running these commands guarantees they're set correctly regardless of how your project was created.

### Give yourself permission to trigger builds:

Your own user account also needs permission to start builds and access storage:

```bash
MY_EMAIL=$(gcloud config get-value account)

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="user:${MY_EMAIL}" \
    --role="roles/cloudbuild.builds.editor" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="user:${MY_EMAIL}" \
    --role="roles/storage.admin" --quiet
```

**Not sure what email you're logged in as?** Run:
```bash
gcloud auth list
```
The account with the asterisk (*) next to it is your active account.

### Give yourself permission to use the service account:

When you deploy to Cloud Run in Step 8, you tell Cloud Run to use the service account you just created. Google needs to verify that YOU are allowed to assign that service account to a service. Without this, the deploy command will fail with "Permission 'iam.serviceaccounts.actAs' denied."

```bash
gcloud iam service-accounts add-iam-policy-binding \
    native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com \
    --member="user:${MY_EMAIL}" \
    --role="roles/iam.serviceAccountUser"
```

**What this does:** It says "this user is allowed to deploy services that run as this service account." It's a security control — Google doesn't let just anyone assign service accounts to running services.

---

## Step 5: Add Your VirusTotal API Key (Optional But Recommended)

This lets the server look up IPs, domains, and file hashes in VirusTotal. **Skip this step if you don't have a VT account.**

### Get a free VirusTotal API key:

1. Go to **https://www.virustotal.com/gui/join-us**
2. Create an account (free)
3. Once logged in, click your avatar (top right) → **"API Key"**
4. Copy the long string of letters and numbers — that's your key

### Store it securely in Google Cloud:

```bash
echo -n "PASTE_YOUR_API_KEY_HERE" | gcloud secrets create gti-api-key \
    --data-file=- \
    --replication-policy="automatic"
```

**Replace `PASTE_YOUR_API_KEY_HERE`** with the actual key you just copied. Keep the quotes.

Now let the service account read the secret:

```bash
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud secrets add-iam-policy-binding gti-api-key \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" --quiet
```

**If you see "already exists":** The secret was created before. To update it with a new key:
```bash
echo -n "YOUR_NEW_KEY" | gcloud secrets versions add gti-api-key --data-file=-
```

---

## Step 6: Find Your SecOps Customer ID

Your MCP server needs to know which SecOps instance to connect to. That's identified by a "Customer ID."

### How to find it:

1. Open **Google SecOps** in your browser (the Chronicle console)
2. Click the **gear icon** (Settings) in the bottom-left
3. Click **"SIEM Settings"**
4. Look for **"Customer ID"** — it's a long string that looks like: `1d49deb2eaa7427ca1d1e78ccaa91c10`
5. **Copy it.** You'll paste it in the next step.

**Also note your region:**
- If your SecOps URL contains `us-chronicle` → your region is `us`
- If it contains `europe-chronicle` → your region is `europe`
- If it contains `asia-chronicle` → your region is `asia`

---

## Step 7: Build the Container

This is where Google takes your code and packages it into a Docker container. **This happens in Google's cloud — you don't need Docker installed on your computer.**

First, create a container registry to store your built images:

```bash
PROJECT_ID=$(gcloud config get-value project)

gcloud artifacts repositories create mcp-server \
    --repository-format=docker \
    --location=us-central1 \
    --project=${PROJECT_ID} \
    --description="MCP Server container images"
```

**What this does:** Creates a place in Google Cloud to store your Docker container images. Think of it as a private folder for your server's code packages.

**If you see "already exists":** That's fine. It was created before. Keep going.

Now build the container:

```bash
gcloud builds submit --tag us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest
```

**What happens:**
1. Google uploads your code files (~50KB — takes a few seconds)
2. Google reads the `Dockerfile` and installs all the Python packages
3. Google saves the finished container to your project's Container Registry

**This takes 2–5 minutes.** You'll see a lot of text scrolling by. That's normal. Wait for the final line:

```
DONE
```

**If you see an error about "Cloud Build API":** Go back to Step 3 and make sure you enabled `cloudbuild.googleapis.com`.

**If you see "permission denied" or "storage.objects.get" error:** Go back to Step 4 and make sure you ran the Cloud Build service account permission commands.

**If you see "repo does not exist" or "createOnPush" error:** You missed the `gcloud artifacts repositories create` command above. Run it first, then retry the build.

**If you see a Python error about "mcp" or "requirements":** The `requirements.txt` file might be out of date. This shouldn't happen with the latest code, but if it does, let me know.

---

## Step 8: Deploy to Cloud Run

This is the big moment. This command takes the container you just built and runs it on Google's servers, giving you a live URL.

```bash
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"
SECOPS_CUSTOMER_ID="PASTE_YOUR_CUSTOMER_ID_HERE"
SECOPS_REGION="us"

gcloud run deploy google-native-mcp \
    --image us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest \
    --region us-central1 \
    --service-account ${SA_EMAIL} \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 120 \
    --set-env-vars="SECOPS_PROJECT_ID=${PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=${SECOPS_REGION}" \
    --quiet
```

⚠️ **Before you paste this:** Replace `PASTE_YOUR_CUSTOMER_ID_HERE` with the Customer ID you copied in Step 6.

⚠️ **If your SecOps region isn't `us`:** Change `SECOPS_REGION="us"` to `"europe"` or `"asia"`.

**What each flag means (you don't need to change these):**

| Flag | What It Does |
|---|---|
| `--image` | Points to the container you built in Step 7 |
| `--region us-central1` | Runs the server in Google's Iowa data center (cheapest) |
| `--service-account` | Tells the server to use the identity you created in Step 4 |
| `--no-allow-unauthenticated` | Requires a valid token to access (security!) |
| `--memory 512Mi` | Gives the server 512MB of RAM (plenty for API proxying) |
| `--min-instances 0` | Server sleeps when no one is using it ($0 when idle!) |
| `--max-instances 10` | Caps at 10 copies if many people use it at once |
| `--timeout 120` | Allows requests to take up to 2 minutes (some SecOps queries are slow) |

**What happens:** Google creates your Cloud Run service and gives you a URL. You'll see:

```
Service [google-native-mcp] revision [google-native-mcp-00001-abc] has been deployed
Service URL: https://google-native-mcp-abc123-uc.a.run.app
```

🎉 **That URL is your MCP server.** Copy it. Save it. Bookmark it.

---

## Step 9: Add the VirusTotal Secret (If You Did Step 5)

If you stored a VT API key in Step 5, connect it to your running server:

```bash
gcloud run services update google-native-mcp \
    --region us-central1 \
    --set-secrets="GTI_API_KEY=gti-api-key:latest"
```

Skipped Step 5? Skip this step too.

---

## Step 10: Test It!

Let's make sure everything works.

```bash
SERVICE_URL=$(gcloud run services describe google-native-mcp \
    --region us-central1 \
    --format="value(status.url)")

curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
    ${SERVICE_URL}/health
```

**What you should see:**

```json
{
    "status": "healthy",
    "server": "google-native-mcp",
    "version": "2.0.0",
    "tools": 22,
    "project": "secops-mcp",
    "region": "us",
    "integrations": {
        "gti": true,
        "o365": false,
        "okta": false,
        "azure_ad": false,
        "aws": false,
        "crowdstrike": false
    }
}
```

**What this means:**
- `"status": "healthy"` → ✅ Your server is running!
- `"tools": 22` → ✅ All 22 security tools are loaded
- `"gti": true` → ✅ VirusTotal integration is working (false if you skipped Step 5)
- `"o365": false` → That's fine — you haven't configured O365 integration yet
- Other `false` values → Also fine — those integrations are optional

### 🎉 IF YOU SEE "healthy" — CONGRATULATIONS. YOU'RE DONE.

Your autonomous security operations server is live on Google Cloud. It costs $0 when nobody is using it, and scales automatically when someone does.

---

## Step 11: Connect an AI to Your Server

Your server is running, but it's just sitting there waiting. You need to connect an AI client to actually use the 22 tools.

### Option A: Claude Code (If You Use Claude)

```bash
SERVICE_URL=$(gcloud run services describe google-native-mcp \
    --region us-central1 \
    --format="value(status.url)")

claude mcp add google-security --transport sse ${SERVICE_URL}/sse
```

Now every time you use Claude Code, it can access all 22 security tools.

### Option B: Any MCP-Compatible Client

Your server's endpoints:

| Endpoint | What It's For |
|---|---|
| `https://YOUR_URL/health` | Health check (test with curl) |
| `https://YOUR_URL/sse` | MCP client connection (SSE streaming) |

Every request needs an authorization header:
```
Authorization: Bearer YOUR_TOKEN
```

Get a token with:
```bash
gcloud auth print-identity-token
```

---

## How to See Your Server in the Google Cloud Console

Want to see your server in a web browser instead of the terminal?

1. Go to **https://console.cloud.google.com/run**
2. Make sure your project is selected at the top
3. You'll see `google-native-mcp` in the list
4. Click on it to see:
   - The URL
   - How many requests it's handling
   - Logs (what the server is doing)
   - Metrics (CPU, memory, response times)

---

## How to Update Your Server Later

If the code gets updated on GitHub:

```bash
cd ~/Desktop/Google-Native-MCP-Server    # or wherever you downloaded it
git pull                                   # get the latest code

PROJECT_ID=$(gcloud config get-value project)
gcloud builds submit --tag us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest
gcloud run deploy google-native-mcp \
    --image us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest \
    --region us-central1
```

That rebuilds the container and redeploys. Zero downtime — the old version keeps running until the new one is ready.

---

## How to Delete Everything (Clean Removal)

If you want to remove the server completely:

```bash
PROJECT_ID=$(gcloud config get-value project)

# Delete the Cloud Run service
gcloud run services delete google-native-mcp --region us-central1 --quiet

# Delete the service account
gcloud iam service-accounts delete native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com --quiet

# Delete the VT API key secret (if you created one)
gcloud secrets delete gti-api-key --quiet
```

After this, nothing remains. No charges. No resources. Clean slate.

---

## Troubleshooting — When Things Go Wrong

### "gcloud: command not found"
You haven't installed the Google Cloud CLI. Go back to "Thing 3" at the top.

### "PERMISSION_DENIED" on anything
You don't have enough permissions on the GCP project. You need to be a **Project Owner** or **Editor**. Ask your admin to run:
```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT \
    --member="user:YOUR_EMAIL" \
    --role="roles/editor"
```

### Cloud Build fails
Look at the error message. The most common cause is a Python dependency issue. Run this to see the build log:
```bash
gcloud builds list --limit=1
gcloud builds log $(gcloud builds list --limit=1 --format="value(id)")
```

### Health check returns "degraded"
The service account doesn't have the right permissions. Re-run the permission commands in Step 4.

### curl returns "403 Forbidden"
Your identity token expired (they last 1 hour). Get a fresh one:
```bash
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ${SERVICE_URL}/health
```

### curl returns "Connection refused" or times out
The server might be sleeping (min-instances = 0). The first request takes 2–3 seconds to "wake up" the server. Try again — the second request will be fast.

### I changed my SecOps Customer ID and need to update
```bash
gcloud run services update google-native-mcp \
    --region us-central1 \
    --set-env-vars="SECOPS_CUSTOMER_ID=your-new-customer-id"
```

---

## The Speed Run (For People Who Don't Need Hand-Holding)

The entire deployment in one block:

```bash
# Setup
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
git clone https://github.com/dnehoda-source/Google-Native-MCP-Server.git
cd Google-Native-MCP-Server

# Enable APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com securitycenter.googleapis.com logging.googleapis.com aiplatform.googleapis.com chronicle.googleapis.com

# Service account
gcloud iam service-accounts create native-mcp-sa --display-name="MCP Server"
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"
for ROLE in roles/chronicle.viewer roles/securitycenter.findingsViewer roles/logging.viewer roles/aiplatform.user; do
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:${SA_EMAIL}" --role="$ROLE" --quiet
done

# Create container registry + Build + Deploy
gcloud artifacts repositories create mcp-server --repository-format=docker --location=us-central1 --project=${PROJECT_ID} 2>/dev/null
gcloud builds submit --tag us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest
gcloud run deploy google-native-mcp --image us-central1-docker.pkg.dev/${PROJECT_ID}/mcp-server/google-native-mcp:latest --region us-central1 --service-account ${SA_EMAIL} --no-allow-unauthenticated --memory 512Mi --set-env-vars="SECOPS_PROJECT_ID=${PROJECT_ID},SECOPS_CUSTOMER_ID=YOUR_CUSTOMER_ID,SECOPS_REGION=us" --quiet

# Test
SERVICE_URL=$(gcloud run services describe google-native-mcp --region us-central1 --format="value(status.url)")
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ${SERVICE_URL}/health
```
