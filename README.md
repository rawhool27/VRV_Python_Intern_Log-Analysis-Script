# Python-Intern
Assignments - VRV Security
### 1. **Requests per IP**
- This section lists the number of requests made by each IP address.
  - `IP Address`: The IP address from which the requests originated.
  - `Request Count`: The total number of requests made by the IP address.
 

### 2. **Most Accessed Endpoint**
- This section identifies the endpoint (URL or resource path) that was accessed the most number of times.
  - `Endpoint`: The most frequently accessed resource.
  - `Access Count`: The number of times this endpoint was accessed.

### 3. **Suspicious Activity**
- This section flags IP addresses with suspicious behavior, such as excessive failed login attempts.
  - `IP Address`: The IP address exhibiting suspicious activity.
  - `Failed Login Count`: The total number of failed login attempts from the IP address.

---
### [**Log Analysis Results**](https://github.com/Dharunkumar-S/Python-Intern/blob/main/log_analysis_results.csv)
1. **Count Requests per IP Address**:
   
    ```bash
        IP Address           Request Count
        192.168.1.1          69
        203.0.113.5          8
        198.51.100.23        8
        10.0.0.2             6
        192.168.1.100        5
    ```

  2. **Identify the Most Frequently Accessed Endpoint**:

     ```bash
        Most Frequently Accessed Endpoint:
        Endpoint              Access Count
        /home                 67
     ```
  3. **Detect Suspicious Activity**:

     ```bash
        Suspicious Activity Detected:
        IP Address           Failed Login Attempts
        ```
---

###  [**Log_Analysis.py**](https://github.com/Dharunkumar-S/Python-Intern/blob/main/log_analysis.py)

```python
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

```

---
### **Terminal Output**:

```bash
Requests per IP Address:
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
10.0.0.2             6
192.168.1.100        5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
No suspicious activity detected.

Results saved to log_analysis_results.csv
```
---

### [**Sample.log**](https://github.com/Dharunkumar-S/Python-Intern/blob/main/sample.log)

```bash
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768
192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256
203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024
192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256
198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128
```
