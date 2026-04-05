import sys
from collections import defaultdict

def analyze_log(file_path):
    ip_count = defaultdict(int)
    status_count = defaultdict(int)
    page_count = defaultdict(int)
    ip_errors = defaultdict(int)
    ip_pages = defaultdict(set)

    total_requests = 0

    try:
        with open(file_path, "r") as f:
            for line in f:
                parts = line.split()

                if len(parts) < 9:
                    continue

                ip = parts[0]
                page = parts[6]
                status = parts[8]
                total_requests += 1
                ip_count[ip] += 1
                page_count[page] += 1
                status_count[status] += 1
                ip_pages[ip].add(page)

                if status.startswith("4") or status.startswith("5"):
                    ip_errors[ip] += 1

    except FileNotFoundError:
        print("File not found")
        return

    print(f"Total Requests: {total_requests}")
    print(f"Unique IPs: {len(ip_count)}")
    print("\nTop 5 IP Addresses:")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} - {count} requests")

    print("\nSuspicious IPs:")
    found = False
    for ip in ip_count:
        reasons = []

        if ip_count[ip] > 5:
            reasons.append("High traffic")

        if ip_errors[ip] > 5:
            reasons.append("High error rate")

        if len(ip_pages[ip]) > 5:
            reasons.append("Scanning many pages")

        if reasons: 
            print(f"{ip} - {', '.join(reasons)}")
            found = True

    if not found:
        print("No obvious suspicious activity detected.")

    print("\nTop 5 Requested Pages:")
    for page, count in sorted(page_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{page} - {count} requests")

    print("\nHTTP Code Summary:")
    for status, count in sorted(status_count.items()):
        print(f"{status} - {count}")

    error_total = sum(count for status, count in status_count.items() if status.startswith("4") or status.startswith("5"))
    if total_requests > 0:
        error_rate = (error_total / total_requests) * 100
        print(f"\nError Rate: {error_rate:.2f}%")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Format: python log-tool.py <log-file>")
    else:
        analyze_log(sys.argv[1])