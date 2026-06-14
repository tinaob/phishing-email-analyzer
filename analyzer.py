import email
import re
import requests

# ---- PASTE YOUR VIRUSTOTAL API KEY HERE ----
API_KEY = "03a8de1534067a3e83ec041f1e56eafed326ae0f929e49ce6ec8d99e75661446"

# ---- STEP 1: Load the email file ----
def load_email(file_path):
    with open(file_path, "r", errors="ignore") as f:
        msg = email.message_from_file(f)
    return msg

# ---- STEP 2: Extract useful information ----
def extract_info(msg):
    print("\n===== EMAIL HEADER ANALYSIS =====")
    print(f"From:     {msg.get('From')}")
    print(f"To:       {msg.get('To')}")
    print(f"Subject:  {msg.get('Subject')}")
    print(f"Reply-To: {msg.get('Reply-To')}")
    print(f"Date:     {msg.get('Date')}")

    sender = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    if reply_to and reply_to != sender:
        print("\n⚠️  WARNING: Reply-To differs from sender — possible phishing indicator!")

# ---- STEP 3: Extract URLs from the email body ----
def extract_urls(msg):
    urls = []
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    found = re.findall(r'https?://[^\s\'"<>]+', body)
    urls = list(set(found))

    print(f"\n===== URLS FOUND IN EMAIL: {len(urls)} =====")
    for url in urls:
        print(f"  → {url}")

    return urls

# ---- STEP 4: Check each URL against VirusTotal ----
def check_virustotal(urls):
    print("\n===== VIRUSTOTAL SCAN RESULTS =====")

    for url in urls:
        headers = {"x-apikey": API_KEY}
        params = {"url": url}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=params
        )

        if response.status_code == 200:
            result = response.json()
            scan_id = result["data"]["id"]

            analysis = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers
            ).json()

            stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                print(f"\n🚨 MALICIOUS URL DETECTED!")
                print(f"   URL: {url}")
                print(f"   Flagged by {malicious} security engines as malicious")
            elif suspicious > 0:
                print(f"\n⚠️  Suspicious URL:")
                print(f"   URL: {url}")
                print(f"   Flagged by {suspicious} engines as suspicious")
            else:
                print(f"\n✅ URL appears clean: {url}")
        else:
            print(f"\n❌ Could not scan: {url} (API error {response.status_code})")

# ---- MAIN: Run everything ----
def main():
    email_file = "test_phishing.eml"

    print(f"Analyzing: {email_file}")
    msg = load_email(email_file)
    extract_info(msg)
    urls = extract_urls(msg)

    if urls:
        check_virustotal(urls)
    else:
        print("\nNo URLs found in email body.")

    print("\n===== ANALYSIS COMPLETE =====")

main()