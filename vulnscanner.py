import argparse
import subprocess
import socket
import ipaddress
from datetime import datetime
from jinja2 import Template

class FastScanner:
    def __init__(self):
        self.result = ""
        self.start_time = None
        self.end_time = None

    def validate_target(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def scan(self, target):
        if not self.validate_target(target):
            print("[-] Invalid IP or domain.")
            return False

        self.start_time = datetime.now()
        print(f"[+] Starting fast scan on {target} at {self.start_time}")

        # استخدم nmap مع أوامر خفيفة و timeout فعلي
        try:
            result = subprocess.run(
                ["nmap", "-T4", "-F", "-Pn", "--host-timeout", "30s", target],
                capture_output=True, text=True, timeout=40
            )
            self.result = result.stdout
            self.end_time = datetime.now()
            print(self.result)
            return True
        except subprocess.TimeoutExpired:
            print("[-] Scan timed out after 40 seconds.")
            return False
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return False

    def generate_report(self):
        duration = str(self.end_time - self.start_time)
        html_template = """
        <html>
        <head><title>Fast Scan Report</title></head>
        <body>
            <h2>Scan Report for {{ target }}</h2>
            <p><strong>Start Time:</strong> {{ start_time }}</p>
            <p><strong>End Time:</strong> {{ end_time }}</p>
            <p><strong>Duration:</strong> {{ duration }}</p>
            <pre>{{ result }}</pre>
        </body>
        </html>
        """
        template = Template(html_template)
        output = template.render(
            target=args.target,
            start_time=self.start_time,
            end_time=self.end_time,
            duration=duration,
            result=self.result
        )

        with open("fast_scan_report.html", "w", encoding="utf-8") as f:
            f.write(output)
        print("[+] Report saved to fast_scan_report.html")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast Nmap Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    args = parser.parse_args()

    scanner = FastScanner()
    if scanner.scan(args.target):
        scanner.generate_report()
