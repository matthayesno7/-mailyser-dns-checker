from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import os
import dns.resolver
import re
from datetime import datetime

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class EmailDNSCheckRequest(BaseModel):
    email: EmailStr

class DNSRecord(BaseModel):
    type: str
    status: str  # "valid", "invalid", "missing"
    record: Optional[str] = None
    issues: List[str] = []
    recommendations: List[str] = []

class EmailDNSCheckResponse(BaseModel):
    email: str
    domain: str
    overall_status: str  # "pass", "warning", "fail"
    spf: DNSRecord
    dmarc: DNSRecord
    dkim: DNSRecord
    timestamp: datetime

# DNS checking functions (same as before)
def extract_domain(email: str) -> str:
    return email.split('@')[1].lower()

def check_spf_record(domain: str) -> DNSRecord:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=spf1')]
        
        if not spf_records:
            return DNSRecord(
                type="SPF",
                status="missing",
                issues=["No SPF record found"],
                recommendations=[
                    "Add an SPF record to your DNS",
                    "Example: v=spf1 include:_spf.google.com ~all"
                ]
            )
        
        if len(spf_records) > 1:
            return DNSRecord(
                type="SPF",
                status="invalid",
                record=spf_records[0],
                issues=["Multiple SPF records found - only one is allowed"],
                recommendations=["Combine all SPF mechanisms into a single record"]
            )
        
        spf_record = spf_records[0]
        issues = []
        recommendations = []
        
        if not spf_record.endswith(('~all', '-all', '?all')):
            issues.append("SPF record should end with an 'all' mechanism")
            recommendations.append("Add ~all (softfail) or -all (hardfail) at the end")
        
        if spf_record.count('include:') > 10:
            issues.append("Too many include mechanisms may cause DNS lookup limit issues")
            recommendations.append("Consolidate include mechanisms to reduce DNS lookups")
        
        status = "valid" if not issues else "warning"
        
        return DNSRecord(
            type="SPF",
            status=status,
            record=spf_record,
            issues=issues,
            recommendations=recommendations
        )
        
    except dns.resolver.NXDOMAIN:
        return DNSRecord(
            type="SPF",
            status="invalid",
            issues=["Domain does not exist"],
            recommendations=["Verify the domain name is correct"]
        )
    except Exception as e:
        return DNSRecord(
            type="SPF",
            status="invalid",
            issues=[f"Error checking SPF: {str(e)}"],
            recommendations=["Check DNS configuration"]
        )

def check_dmarc_record(domain: str) -> DNSRecord:
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('"v=DMARC1')]
        
        if not dmarc_records:
            return DNSRecord(
                type="DMARC",
                status="missing",
                issues=["No DMARC record found"],
                recommendations=[
                    "Add a DMARC record to your DNS",
                    "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
                ]
            )
        
        dmarc_record = dmarc_records[0]
        issues = []
        recommendations = []
        
        policy_match = re.search(r'p=([^;]+)', dmarc_record)
        if not policy_match:
            issues.append("No policy (p=) specified in DMARC record")
            recommendations.append("Add a policy like p=quarantine or p=reject")
        else:
            policy = policy_match.group(1).strip()
            if policy == "none":
                issues.append("DMARC policy is set to 'none' - emails won't be protected")
                recommendations.append("Consider upgrading to p=quarantine or p=reject")
        
        if 'rua=' not in dmarc_record and 'ruf=' not in dmarc_record:
            issues.append("No reporting addresses specified")
            recommendations.append("Add rua= for aggregate reports")
        
        status = "valid" if not issues else "warning"
        
        return DNSRecord(
            type="DMARC",
            status=status,
            record=dmarc_record,
            issues=issues,
            recommendations=recommendations
        )
        
    except dns.resolver.NXDOMAIN:
        return DNSRecord(
            type="DMARC",
            status="missing",
            issues=["No DMARC record found"],
            recommendations=[
                "Add a DMARC record to your DNS",
                "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
            ]
        )
    except Exception as e:
        return DNSRecord(
            type="DMARC",
            status="invalid",
            issues=[f"Error checking DMARC: {str(e)}"],
            recommendations=["Check DNS configuration"]
        )

def check_dkim_record(domain: str) -> DNSRecord:
    common_selectors = [
        'default', 'selector1', 'selector2', 'google', 'k1', 'dkim', 
        'mail', 'email', 'mxvault', 'pps1', 'x'
    ]
    
    found_records = []
    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = str(rdata).strip('"')
                if 'v=DKIM1' in record or 'k=rsa' in record:
                    found_records.append({
                        'selector': selector,
                        'record': record
                    })
        except:
            continue
    
    if not found_records:
        return DNSRecord(
            type="DKIM",
            status="missing",
            issues=["No DKIM records found with common selectors"],
            recommendations=[
                "Set up DKIM signing for your email service",
                "Common selectors checked: " + ", ".join(common_selectors[:5]) + "..."
            ]
        )
    
    first_record = found_records[0]
    issues = []
    recommendations = []
    
    if 'k=rsa' in first_record['record']:
        if 'b=MII' not in first_record['record']:
            issues.append("DKIM key might be shorter than recommended 2048 bits")
            recommendations.append("Consider using RSA-2048 or higher for better security")
    
    status = "valid" if not issues else "warning"
    
    return DNSRecord(
        type="DKIM",
        status=status,
        record=f"Selector: {first_record['selector']} - {first_record['record'][:100]}...",
        issues=issues,
        recommendations=recommendations
    )

def determine_overall_status(spf: DNSRecord, dmarc: DNSRecord, dkim: DNSRecord) -> str:
    statuses = [spf.status, dmarc.status, dkim.status]
    
    valid_count = statuses.count("valid")
    warning_count = statuses.count("warning")
    missing_count = statuses.count("missing")
    invalid_count = statuses.count("invalid")
    
    if valid_count >= 2 and invalid_count == 0 and missing_count == 0:
        return "pass"
    elif valid_count >= 1 and invalid_count == 0 and missing_count == 0:
        return "pass"
    elif missing_count >= 2 or invalid_count >= 1:
        return "fail"
    else:
        return "warning"

@app.get("/")
async def root():
    return {"message": "Mailyser DNS Checker API"}

@app.post("/check-dns", response_model=EmailDNSCheckResponse)
async def check_email_dns(request: EmailDNSCheckRequest):
    try:
        domain = extract_domain(request.email)
        
        spf = check_spf_record(domain)
        dmarc = check_dmarc_record(domain)
        dkim = check_dkim_record(domain)
        
        overall_status = determine_overall_status(spf, dmarc, dkim)
        
        response = EmailDNSCheckResponse(
            email=request.email,
            domain=domain,
            overall_status=overall_status,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            timestamp=datetime.utcnow()
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error checking DNS: {str(e)}")