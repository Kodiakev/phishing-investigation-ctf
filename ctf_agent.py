
import asyncio
import base64
import json
import re
from pathlib import Path
from playwright.async_api import async_playwright

BASE_URL = "https://www.darkwaterfinancial.ca"
OUTPUT_FILE = Path("evidence.example.json")

# Use dummy credentials authorised by the CTF.
TEST_USERNAME = "ctf-test@example.com"
TEST_PASSWORD = "CTF-Test-12345!"


def decode_payload(encoded_payload):
    """Decode the Base64-encoded JSON payload twice."""
    decoded = base64.b64decode(encoded_payload)
    decoded = base64.b64decode(decoded)
    return json.loads(decoded.decode("utf-8"))


def redact_evidence(payload):
    """Remove identifying and sensitive values before saving evidence."""
    sensitive_fields = {
        "ip_address": "[REDACTED]",
        "username": "[TEST ACCOUNT]",
        "password": "[REDACTED]",
        "geo_postal": "[REDACTED]",
        "geo_latitude": "[REDACTED]",
        "geo_longitude": "[REDACTED]",
    }

    safe_payload = dict(payload)

    for field, replacement in sensitive_fields.items():
        if field in safe_payload:
            safe_payload[field] = replacement

    # Avoid publishing precise event timing from a real session.
    if "timestamp" in safe_payload:
        safe_payload["timestamp"] = "[REDACTED]"

    return safe_payload


async def main():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False)

        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            locale="en-GB",
            timezone_id="Europe/London",
        )

        page = await context.new_page()
        captured_payload = None

        async def inspect_request(request):
            nonlocal captured_payload

            if (
                request.url.endswith("/session")
                and request.method == "GET"
            ):
                encoded = request.headers.get("x-payload")

                if encoded:
                    try:
                        captured_payload = decode_payload(encoded)
                        print("[+] Session payload captured and decoded")
                    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                        print(f"[!] Could not decode payload: {exc}")

        page.on("request", inspect_request)

        try:
            print("[+] Opening CTF website")
            await page.goto(
                BASE_URL,
                wait_until="domcontentloaded",
                timeout=30000,
            )

            # Wait for the challenge's own browser-validation workflow.
            await page.wait_for_url(
                re.compile(r"/landing(?:\?.*)?$"),
                timeout=20000,
            )

            print("[+] Browser validation completed")

            await page.goto(
                f"{BASE_URL}/login",
                wait_until="domcontentloaded",
            )

            await page.locator("#email").fill(TEST_USERNAME)
            await page.locator("#password").fill(TEST_PASSWORD)

            print("[+] Submitting controlled test credentials")

            await page.locator(
                'button[type="submit"]'
            ).click()

            # Allow the browser to issue the session request.
            try:
                await page.wait_for_function(
                    "() => document.body.innerText.includes('Invalid credentials')",
                    timeout=10000,
                )
            except Exception:
                print("[!] Expected login response was not observed")

            # Give the request listener time to process the captured event.
            await page.wait_for_timeout(1000)

            if captured_payload is None:
                print("[!] No decodable X-Payload was captured")
                return

            safe_payload = redact_evidence(captured_payload)

            OUTPUT_FILE.write_text(
                json.dumps(safe_payload, indent=2),
                encoding="utf-8",
            )

            print("[+] Sanitised evidence saved")
            print(json.dumps(safe_payload, indent=2))

        finally:
            await context.close()
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
