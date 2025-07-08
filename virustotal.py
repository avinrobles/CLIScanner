import requests, sys, time, os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
API_KEY = os.getenv("YOUR_API_KEY") # Retrieve API key from environment variables
HEADERS = {"x-apikey": API_KEY} # Headers for API requests, including the API key
BASE_URL = "https://www.virustotal.com/api/v3" # Base URL for VirusTotal API endpoints

# Function to handle the analysis of the report
def analysis(report_url):
    while True:
        response = requests.get(report_url, headers=HEADERS)
        data = response.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            print("trying again in 10 seconds...") # Print message indicating the script is waiting for the analysis to complete
            time.sleep(10) # Wait for 2 seconds before checking the status again
            return data # Return the completed analysis data

# Function to scan a URL using the VirusTotal API
def scan_url(target_url):
    print(f"Submitting URL for analysis: {target_url}") # Print the URL being scanned
    response = requests.post(f"{BASE_URL}/urls", headers=HEADERS, data={"url": target_url})
    if response.status_code != 200:
        print("Error submitting URL:", response.json()) # Print the error message if submission fails
        return

    # Extract the analysis ID from the response
    analysis_id = response.json()["data"]["id"]
    print(f"URL Submitted with analysis id: {analysis_id}") # This ID is used to retrieve the analysis report later
    print("[*] Waiting for analysis report...") # Wait for the analysis to complete

    # Wait for the analysis to complete and retrieve the report
    report_url = f"{BASE_URL}/analyses/{analysis_id}"
    data = analysis(report_url)
    stats = data["data"]["attributes"]["stats"] # Statistics of the scan results
    scan_time = data["data"]["attributes"]["date"] # Timestamp of the scan

    # Print the scan results
    print("Scan Results:")
    print(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_time))}")
    for category in ["harmless", "malicious", "suspicious", "undetected", "timeout"]: # Categories of scan results
        print(f"  {category.capitalize()}: {stats.get(category, 0)}")

# Function to scan a file using the VirusTotal API
def scan_file(file_path):
    if not os.path.isfile(file_path): # Check if the file exists
        print(f"File not found: {file_path}") # Print if file is not found/ does not exist in directory
        return

    print(f"[+] Uploading file: {file_path}") # Print the file being uploaded
    response = requests.post(f"{BASE_URL}/files", headers=HEADERS, files={"file": open(file_path, "rb")})
    if response.status_code != 200:
        print("Error uploading file:", response.json()) # Print the error message if upload fails
        return

    analysis_id = response.json()["data"]["id"] # Extract the analysis ID from the response
    print("[*] Waiting for analysis report...") # Wait for the analysis to complete

    report_url = f"{BASE_URL}/analyses/{analysis_id}" # URL to retrieve the analysis report
    data = analysis(report_url) 
    stats = data["data"]["attributes"]["stats"] # Statistics of the scan results (similar to what URL scan did)
    scan_time = data["data"]["attributes"]["date"] # Timestamp of the scan (same as URL scan)

    print("Scan Results:") # Print the scan results
    print(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_time))}")
    for category in ["harmless", "malicious", "suspicious", "undetected", "timeout"]:
        print(f"  {category.capitalize()}: {stats.get(category, 0)}")

# Main function to execute the script
if __name__ == "__main__":
    if len(sys.argv) < 3: # Check if the correct number of arguments is provided
        print("Usage: python virustotal.py url <url> or python virustotal.py file <file path>")
        sys.exit(1)

    # Assigns the url or file mode of the script [mode] and real-life urls and files [target]
    mode = sys.argv[1]
    target = sys.argv[2]

    # Check the mode and call the appropriate function
    if mode == "url":
        scan_url(target)
    elif mode == "file":
        scan_file(target)
    elif mode == "help":
        print("Usage: python virustotal.py url <url> or python virustotal.py file <file path>")
    else:
        print("Invalid mode. Use 'url' or 'file'.")
        sys.exit(1)
