import re
import csv
from collections import defaultdict

def parse_log_file(log_file_path):
    """
    Parse the log file and extract relevant information.
    
    Args:
        log_file_path (str): Path to the log file
    
    Returns:
        tuple: Contains dictionaries for IP requests, endpoints, and failed logins
    """
    # Dictionaries to store analysis results
    ip_requests = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)
    
    # Regular expression to parse log entries
    log_pattern = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+).*"(GET|POST|PUT|DELETE)\s+(/\w+).*"\s+(\d+)'
    )
    
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                # Match log entry pattern
                match = log_pattern.match(line)
                if match:
                    ip_address = match.group(1)
                    method = match.group(2)
                    endpoint = match.group(3)
                    status_code = match.group(4)
                    
                    # Count requests per IP
                    ip_requests[ip_address] += 1
                    
                    # Count endpoint access
                    endpoint_counts[endpoint] += 1
                    
                    # Detect failed login attempts
                    if (status_code == '401' or 
                        'Invalid credentials' in line or 
                        'login failed' in line.lower()):
                        failed_login_attempts[ip_address] += 1
    
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return None, None, None
    
    return ip_requests, endpoint_counts, failed_login_attempts

def analyze_log(log_file_path, failed_login_threshold=10):
    """
    Perform comprehensive log analysis.
    
    Args:
        log_file_path (str): Path to the log file
        failed_login_threshold (int): Threshold for suspicious login attempts
    """
    # Parse log file
    ip_requests, endpoint_counts, failed_login_attempts = parse_log_file(log_file_path)
    
    if not ip_requests:
        return
    
    # 1. Requests per IP Address
    print("\n--- Requests per IP Address ---")
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_requests:
        print(f"{ip:<18} {count:>5} requests")
    
    # 2. Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
    print(f"\n--- Most Frequently Accessed Endpoint ---")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # 3. Suspicious Activity Detection
    print("\n--- Suspicious Activity Detection ---")
    suspicious_ips = {
        ip: count for ip, count in failed_login_attempts.items() 
        if count > failed_login_threshold
    }
    
    if suspicious_ips:
        print("Potential Brute Force Attempts:")
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<18} {count:>5} failed login attempts")
    else:
        print("No suspicious activity detected.")
    
    # 4. Save results to CSV
    save_results_to_csv(
        sorted_ip_requests, 
        most_accessed_endpoint, 
        suspicious_ips
    )

def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips):
    """
    Save analysis results to a CSV file.
    
    Args:
        ip_requests (list): List of tuples with IP and request counts
        most_accessed_endpoint (tuple): Tuple with endpoint and its count
        suspicious_ips (dict): Dictionary of IPs with failed login attempts
    """
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        # Section 1: Requests per IP
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Requests per IP'])
        csvwriter.writerow(['IP Address', 'Request Count'])
        csvwriter.writerows(ip_requests)
        
        # Blank row between sections
        csvwriter.writerow([])
        
        # Section 2: Most Accessed Endpoint
        csvwriter.writerow(['Most Accessed Endpoint'])
        csvwriter.writerow(['Endpoint', 'Access Count'])
        csvwriter.writerow(most_accessed_endpoint)
        
        # Blank row between sections
        csvwriter.writerow([])
        
        # Section 3: Suspicious Activity
        csvwriter.writerow(['Suspicious Activity'])
        csvwriter.writerow(['IP Address', 'Failed Login Count'])
        csvwriter.writerows(suspicious_ips.items())
    
    print("\nResults saved to log_analysis_results.csv")

def main():
    """
    Main function to run log analysis.
    """
    log_file_path = 'sample.log'  # Default log file path
    analyze_log(log_file_path)

if __name__ == '__main__':
    main()