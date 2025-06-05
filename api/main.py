from http.server import BaseHTTPRequestHandler
import json
import dns.resolver
import re
from datetime import datetime
from urllib.parse import parse_qs

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/' or self.path == '/api':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            response = {"message": "Mailyser DNS Checker API"}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/check-dns' or self.path == '/api/check-dns/':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode('utf-8'))
                
                email = data.get('email')
                if not email:
                    raise ValueError("Email is required")
                
                # Extract domain
                domain = email.split('@')[1].lower()
                
                # Check DNS records
                spf = self.check_spf_record(domain)
                dmarc = self.check_dmarc_record(domain)
                dkim = self.check_dkim_record(domain)
                
                # Determine overall status
                overall_status = self.determine_overall_status(spf, dmarc, dkim)
                
                response = {
                    "email": email,
                    "domain": domain,
                    "overall_status": overall_status,
                    "spf": spf,
                    "dmarc": dmarc,
                    "dkim": dkim,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                error_response = {"detail": f"Error checking DNS: {str(e)}"}
                self.wfile.write(json.dumps(error_response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def check_spf_record(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=spf1')]
            
            if not spf_records:
                return {
                    "type": "SPF",
                    "status": "missing",
                    "record": None,
                    "issues": ["No SPF record found"],
                    "recommendations": ["Add an SPF record to your DNS", "Example: v=spf1 include:_spf.google.com ~all"]
                }
            
            spf_record = spf_records[0]
            issues = []
            recommendations = []
            
            if not spf_record.endswith(('~all', '-all', '?all')):
                issues.append("SPF record should end with an 'all' mechanism")
                recommendations.append("Add ~all (softfail) or -all (hardfail) at the end")
            
            status = "valid" if not issues else "warning"
            
            return {
                "type": "SPF",
                "status": status,
                "record": spf_record,
                "issues": issues,
                "recommendations": recommendations
            }
        except:
            return {
                "type": "SPF",
                "status": "invalid",
                "record": None,
                "issues": ["Error checking SPF record"],
                "recommendations": ["Check DNS configuration"]
            }

    def check_dmarc_record(self, domain):
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=DMARC1')]
            
            if not dmarc_records:
                return {
                    "type": "DMARC",
                    "status": "missing",
                    "record": None,
                    "issues": ["No DMARC record found"],
                    "recommendations": ["Add a DMARC record to your DNS"]
                }
            
            dmarc_record = dmarc_records[0]
            issues = []
            recommendations = []
            
            policy_match = re.search(r'p=([^;]+)', dmarc_record)
            if not policy_match:
                issues.append("No policy specified in DMARC record")
                recommendations.append("Add a policy like p=quarantine or p=reject")
            
            status = "valid" if not issues else "warning"
            
            return {
                "type": "DMARC",
                "status": status,
                "record": dmarc_record,
                "issues": issues,
                "recommendations": recommendations
            }
        except:
            return {
                "type": "DMARC",
                "status": "missing",
                "record": None,
                "issues": ["No DMARC record found"],
                "recommendations": ["Add a DMARC record to your DNS"]
            }

    def check_dkim_record(self, domain):
        common_selectors = ['default', 'selector1', 'google', 'k1']
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    record = str(rdata).strip('"')
                    if 'v=DKIM1' in record or 'k=rsa' in record:
                        return {
                            "type": "DKIM",
                            "status": "valid",
                            "record": f"Selector: {selector}",
                            "issues": [],
                            "recommendations": []
                        }
            except:
                continue
        
        return {
            "type": "DKIM",
            "status": "missing",
            "record": None,
            "issues": ["No DKIM records found"],
            "recommendations": ["Set up DKIM signing for your email service"]
        }

    def determine_overall_status(self, spf, dmarc, dkim):
        statuses = [spf["status"], dmarc["status"], dkim["status"]]
        valid_count = statuses.count("valid")
        missing_count = statuses.count("missing")
        
        if valid_count >= 2:
            return "pass"
        elif missing_count >= 2:
            return "fail"
        else:
            return "warning"
