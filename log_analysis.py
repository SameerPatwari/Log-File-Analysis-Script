import re
import csv
from collections import defaultdict, Counter

# Setting the threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# Initializing input and output files
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    # Reading the log file and returning a list of log entries
    log_entries = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    log_entries.append(line.strip())
    except FileNotFoundError:
        print(f"Error: The log file '{file_path}' does not exist.")
        return []
    except Exception as e:
        print(f"An error occured while reading the log file: {e}")
        return []
    if not log_entries:
        print(f"Warning: The file '{file_path}' is empty or contains no valid log entries.")
    return log_entries

def count_requests_per_ip(log_entries):
    # Counting the number of requests for each ip address
    ip_counts = Counter()
    for entry in log_entries:
        # Using regular expression to match with the IP addresses at the start of each entry
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', entry)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

def find_most_accessed_end_point(log_entries):
    # Finding the most accessed endpoint
    endpoint_counts = Counter()
    for entry in log_entries:
        # Using regular expression to search for valid HTTP request lines and get most accessed endpoints from them 
        match = re.search(r'"(GET|POST|PUT|DELETE) (\S+) HTTP', entry)
        if match:
            endpoint = match.group(2)
            endpoint_counts[endpoint] += 1
    if endpoint_counts:
        most_accessed = endpoint_counts.most_common(1)[0]
        return most_accessed[0], most_accessed[1]
    return None, 0

def detect_suspicious_activity(log_entries):
    # Detecting suspicious activity based on failed login attempts
    failed_logins = defaultdict(int)
    for entry in log_entries:
        # Using regular expression to match with those IP addresses that have failed login attempts
        if '401' in entry or 'Invalid credentials' in entry:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', entry)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    # Filtering IP's which are exceeding the threshold and marking them as flagged
    flagged_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return flagged_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    # Saves the processed results to a CSV file
    try:
        with open(output_file, 'w', newline='') as file:
            writer = csv.writer(file)
            # Writing requests per IP to the CSV
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow([ip, count])
        
            writer.writerow([])

            # Writing the most accessed endpoint to the CSV
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])

            writer.writerow([])

            #writing suspicious activity to the CSV
            writer.writerow(["Suspicious Activity Detected"])
            writer.writerow(["IP Address", "Failed Login Count"])
            if suspicious_ips:
                for ip, count in suspicious_ips.items():
                    writer.writerow([ip, count])
            else:
                writer.writerow(["No suspicious activity detected"])
        print(f"\nResults successfully saved to {OUTPUT_FILE}")
    except Exception as e:
        print(f"An error occured while saving results to the file: {e}")

def main():
    # Parsing the log file
    log_entries = parse_log_file(LOG_FILE)
    if not log_entries:
        return 

    # Analysing the log file
    ip_counts = count_requests_per_ip(log_entries)
    most_accessed_end_point = find_most_accessed_end_point(log_entries)
    suspicious_ips = detect_suspicious_activity(log_entries)

    # Displaying the results on the terminal
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_end_point[0]} (Accessed {most_accessed_end_point[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
            print("No suspicious activity detected")
    
    # Saving results to the CSV file
    save_results_to_csv(ip_counts, most_accessed_end_point, suspicious_ips, OUTPUT_FILE)
    print(f"\nVerify Results at {OUTPUT_FILE}")

if __name__ == "__main__":
    main()