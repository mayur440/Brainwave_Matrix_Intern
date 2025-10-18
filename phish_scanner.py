import requests
import tldextract
from urllib.parse import urlparse
from datetime import datetime
import socket
import ssl
from bs4 import BeautifulSoup
from typing import Dict, List, Optional
import whois

class PhishingLinkScanner:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'secure', 'banking',
            'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'netflix',
            'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'dropbox',
            'docusign', 'irs', 'tax', 'socialsecurity', 'ssn', 'creditcard'
        ]
        
        self.known_phishing_domains = self._load_phishing_domains()

    def _load_phishing_domains(self) -> set:
        # In a real-world scenario, you would load this from a database or API
        return set()

    def scan_url(self, url: str) -> Dict:
        """
        Main function to scan a URL for phishing indicators
        """
        if not self._is_valid_url(url):
            return {"error": "Invalid URL format"}

        results = {
            "url": url,
            "is_safe": True,
            "warnings": [],
            "domain_info": {},
            "ssl_info": {},
            "suspicious_elements": []
        }

        try:
            # Basic URL analysis
            domain_info = self._analyze_domain(url)
            results["domain_info"] = domain_info

            # Check for suspicious keywords in URL
            keyword_matches = self._check_suspicious_keywords(url)
            if keyword_matches:
                results["warnings"].append(f"Suspicious keywords found in URL: {', '.join(keyword_matches)}")
                results["is_safe"] = False

            # Check domain age
            if domain_info.get("domain_age_days", 0) < 30:
                results["warnings"].append(f"New domain ({(domain_info.get('domain_age_days', 0))} days old)")
                results["is_safe"] = False

            # Check SSL certificate
            ssl_info = self._check_ssl_certificate(url)
            results["ssl_info"] = ssl_info
            if not ssl_info.get("is_valid", False):
                results["warnings"].append("Invalid or expired SSL certificate")
                results["is_safe"] = False

            # Check if domain is in known phishing list
            if domain_info.get("domain") in self.known_phishing_domains:
                results["warnings"].append("Domain found in known phishing database")
                results["is_safe"] = False

            # Analyze website content if possible
            try:
                page_content = self._fetch_url_content(url)
                if page_content:
                    content_analysis = self._analyze_page_content(url, page_content)
                    results["suspicious_elements"].extend(content_analysis)
                    if content_analysis:
                        results["is_safe"] = False
            except Exception as e:
                results["warnings"].append(f"Could not analyze page content: {str(e)}")

        except Exception as e:
            results["error"] = f"Error during scan: {str(e)}"
            results["is_safe"] = False

        return results

    def _is_valid_url(self, url: str) -> bool:
        """Check if the URL has a valid format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def _analyze_domain(self, url: str) -> Dict:
        """Extract and analyze domain information"""
        domain_info = {}
        try:
            domain = urlparse(url).netloc
            domain_info["domain"] = domain
            
            # Extract domain parts
            ext = tldextract.extract(domain)
            domain_info["domain_parts"] = {
                "subdomain": ext.subdomain,
                "domain": ext.domain,
                "suffix": ext.suffix
            }
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(domain)
                domain_info["whois"] = {
                    "registrar": whois_info.registrar,
                    "creation_date": str(whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date),
                    "expiration_date": str(whois_info.expiration_date[0] if isinstance(whois_info.expiration_date, list) else whois_info.expiration_date),
                    "name_servers": list(whois_info.name_servers) if whois_info.name_servers else []
                }
                
                # Calculate domain age
                if whois_info.creation_date:
                    creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                    domain_age = datetime.now() - (creation_date if isinstance(creation_date, datetime) else datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S'))
                    domain_info["domain_age_days"] = domain_age.days
                
            except Exception as e:
                domain_info["whois_error"] = str(e)
                
        except Exception as e:
            domain_info["error"] = str(e)
            
        return domain_info

    def _check_suspicious_keywords(self, url: str) -> List[str]:
        """Check for suspicious keywords in the URL"""
        url_lower = url.lower()
        return [kw for kw in self.suspicious_keywords if kw in url_lower]

    def _check_ssl_certificate(self, url: str) -> Dict:
        """Check SSL certificate validity"""
        result = {"is_valid": False, "details": {}}
        try:
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result["is_valid"] = True
                    result["details"] = {
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "version": cert.get('version'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "serial_number": cert.get('serialNumber')
                    }
        except Exception as e:
            result["error"] = str(e)
            
        return result

    def _fetch_url_content(self, url: str, timeout: int = 10) -> Optional[str]:
        """Fetch content from URL with proper headers"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=True)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            return None

    def _analyze_page_content(self, url: str, content: str) -> List[str]:
        """Analyze page content for suspicious elements"""
        suspicious_elements = []
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check for hidden elements
        hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x.lower())
        if hidden_elements:
            suspicious_elements.append(f"Found {len(hidden_elements)} hidden elements")
        
        # Check for iframes
        iframes = soup.find_all('iframe')
        if iframes:
            suspicious_elements.append(f"Found {len(iframes)} iframes")
        
        # Check for suspicious forms
        forms = soup.find_all('form')
        for form in forms:
            if form.get('action', '').startswith(('http://', '//')) and not form['action'].startswith('https'):
                suspicious_elements.append("Form submits to non-HTTPS URL")
        
        # Check for password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            suspicious_elements.append(f"Found {len(password_fields)} password fields")
        
        return suspicious_elements

def main():
    print("=== Phishing Link Scanner ===")
    print("Enter URLs to scan (one per line). Type 'exit' to quit.")
    
    scanner = PhishingLinkScanner()
    
    while True:
        try:
            url = input("\nEnter URL to scan: ").strip()
            if url.lower() == 'exit':
                break
                
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            print(f"\nScanning: {url}")
            result = scanner.scan_url(url)
            
            print("\n=== Scan Results ===")
            print(f"URL: {result['url']}")
            print(f"Status: {'SAFE' if result.get('is_safe', False) else 'SUSPICIOUS'}")
            
            if 'error' in result:
                print(f"Error: {result['error']}")
            
            if result.get('warnings'):
                print("\nWarnings:")
                for warning in result['warnings']:
                    print(f"- {warning}")
            
            if result.get('domain_info'):
                print("\nDomain Information:")
                domain = result['domain_info'].get('domain', 'N/A')
                age = result['domain_info'].get('domain_age_days', 'N/A')
                print(f"- Domain: {domain}")
                print(f"- Age: {age} days" if age != 'N/A' else "- Age: N/A")
            
            if result.get('ssl_info', {}).get('is_valid'):
                print("\nSSL Certificate:")
                print("- Valid: Yes")
                print(f"- Issuer: {result['ssl_info']['details'].get('issuer', {}).get('organizationName', 'Unknown')}")
                print(f"- Expires: {result['ssl_info']['details'].get('not_after', 'Unknown')}")
            
            if result.get('suspicious_elements'):
                print("\nSuspicious Elements:")
                for element in result['suspicious_elements']:
                    print(f"- {element}")
                    
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
