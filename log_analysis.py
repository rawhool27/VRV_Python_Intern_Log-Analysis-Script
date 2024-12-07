import re
import csv
from collections import defaultdict, Counter

LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Function to parse the log file and extract information
def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            # Count requests per IP
            ip_requests[ip] += 1

            # Extract endpoint and status code
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^ ]+) HTTP', line)
            status_code_match = re.search(r'" (\d{3}) ', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Check for failed login attempts (401 status or specific message)
            if status_code_match and int(status_code_match.group(1)) == 401:
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

# Analyze results and save to CSV
def analyze_and_save_results(ip_requests, endpoint_requests, failed_login_attempts):
    # Sort requests per IP
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Find most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)

    # Filter suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("Requests per IP Address:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0][0]} (Accessed {most_accessed_endpoint[0][1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Count Requests per IP Address:
        writer.writerow(["Count Requests per IP Address:"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ip_requests)

        # Write Most Accessed Frequently Endpoint:
        if most_accessed_endpoint:
            writer.writerow([])
            writer.writerow(["Most Accessed Frequently Endpoint:"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0][0], most_accessed_endpoint[0][1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity:"])
        writer.writerow(["IP Address", "Failed Login Attempts:"])
        writer.writerows(suspicious_ips.items())

    print(f"\nResults saved to {OUTPUT_CSV}")

# Main function
if __name__ == "__main__":
    ip_requests, endpoint_requests, failed_login_attempts = parse_log(LOG_FILE)
    analyze_and_save_results(ip_requests, endpoint_requests, failed_login_attempts)
