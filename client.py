"""
Google-Native MCP Client — Terminal Interface
Connects to your MCP server and lets you call any of the 22 tools interactively.
Uses Gemini to understand your questions and pick the right tool automatically.

Usage:
    python3 client.py
"""

import asyncio
import json
import os
import sys
import requests
import google.auth
from google.auth.transport.requests import Request
from mcp import ClientSession
from mcp.client.sse import sse_client

# ─── CONFIG ───────────────────────────────────────────────
MCP_URL = os.getenv(
    "MCP_URL",
    "https://google-native-mcp-672020644906.us-central1.run.app/sse"
)
PROJECT_ID = os.getenv("SECOPS_PROJECT_ID", "tito-436719")
REGION = os.getenv("GCP_REGION", "us-central1")
MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")


def get_access_token():
    """Access token for Vertex AI / Gemini API calls."""
    creds, _ = google.auth.default()
    creds.refresh(Request())
    return creds.token


def get_identity_token():
    """Identity token for Cloud Run authentication."""
    import subprocess
    result = subprocess.run(
        ["gcloud", "auth", "print-identity-token"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to get identity token: {result.stderr}")
    return result.stdout.strip()


def ask_gemini(prompt, tools_desc):
    access_token = get_access_token()
    url = (
        f"https://{REGION}-aiplatform.googleapis.com/v1/"
        f"projects/{PROJECT_ID}/locations/{REGION}/"
        f"publishers/google/models/{MODEL}:generateContent"
    )
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": (
                "You are a security operations analyst. You have these MCP tools:\n"
                f"{tools_desc}\n\n"
                "If the user's question requires a tool, respond with ONLY a JSON object:\n"
                '{"tool": "tool_name", "args": {"param": "value"}}\n\n'
                "If no tool is needed, just answer the question directly."
            )}]},
        },
        timeout=60,
    )
    if resp.status_code == 200:
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    return f"Gemini error [{resp.status_code}]: {resp.text[:300]}"


async def run():
    id_token = get_identity_token()

    print("\n" + "=" * 60)
    print("  Google-Native MCP Client")
    print("=" * 60)
    print(f"  Server:  {MCP_URL.replace('/sse', '')}")
    print(f"  AI:      Gemini ({MODEL})")
    print("=" * 60)
    print("  Type anything. Gemini picks the right tool automatically.")
    print('  Type "tools" to see all 22 tools.')
    print('  Type "quit" to exit.')
    print("=" * 60 + "\n")

    async with sse_client(MCP_URL, headers={"Authorization": f"Bearer {id_token}"}) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            tools_list = tools.tools
            tools_desc = "\n".join(
                [f"- {t.name}: {t.description}" for t in tools_list]
            )

            print(f"✅ Connected — {len(tools_list)} tools loaded\n")

            while True:
                try:
                    user_input = input("You> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nBye!")
                    break

                if not user_input:
                    continue
                if user_input.lower() in ("quit", "exit", "q"):
                    print("Bye!")
                    break
                if user_input.lower() == "tools":
                    print("\nAvailable tools:")
                    for t in tools_list:
                        print(f"  {t.name} — {t.description[:80]}")
                    print()
                    continue

                # Ask Gemini
                gemini_resp = ask_gemini(user_input, tools_desc)

                # Check if Gemini wants to call a tool
                try:
                    if "{" in gemini_resp and '"tool"' in gemini_resp:
                        start = gemini_resp.index("{")
                        end = gemini_resp.rindex("}") + 1
                        call = json.loads(gemini_resp[start:end])

                        tool_name = call["tool"]
                        tool_args = call.get("args", {})

                        print(f"\n⚡ {tool_name}({json.dumps(tool_args)})")
                        result = await session.call_tool(tool_name, tool_args)
                        result_text = result.content[0].text if result.content else "{}"

                        # Pretty print if JSON
                        try:
                            parsed = json.loads(result_text)
                            result_text = json.dumps(parsed, indent=2)
                        except json.JSONDecodeError:
                            pass

                        print(f"\n📊 Result:\n{result_text}\n")

                        # Have Gemini summarize
                        summary = ask_gemini(
                            f"User asked: {user_input}\n\n"
                            f"Tool {tool_name} returned:\n{result_text[:3000]}\n\n"
                            "Summarize the key findings concisely.",
                            tools_desc,
                        )
                        print(f"🤖 {summary}\n")
                    else:
                        print(f"\n🤖 {gemini_resp}\n")

                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"\n🤖 {gemini_resp}\n")


if __name__ == "__main__":
    asyncio.run(run())
