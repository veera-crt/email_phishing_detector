import re
import email
from email import policy
from email.parser import BytesParser
import hashlib
import json
import ipaddress
from urllib.parse import urlparse
import tldextract
from api_dns_integration import APIDNSIntegrator  # Add this import

class EmailAnalyzer:
    def __init__(self, config):
        self.config = config
        self.whitelist = self.load_whitelist()
        self.api_dns_integrator = APIDNSIntegrator(config)  # Initialize the integrator
    
    def load_whitelist(self):
        try:
            with open('whitelist.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "exactMatching": {
                    "mail": [], "ip": [], "url": [], "domain": [],
                    "filename": [], "filetype": [], "hash": []
                },
                "domainsInSubdomains": [],
                "domainsInURLs": [],
                "domainsInEmails": [],
                "regexMatching": {
                    "mail": [], "ip": [], "url": [], "domain": [], "filename": []
                }
            }
    
    def save_whitelist(self):
        with open('whitelist.json', 'w') as f:
            json.dump(self.whitelist, f, indent=4)
    
    def analyze_email(self, filepath):
        """Main analysis function that coordinates all checks"""
        results = {
            'headers': {},
            'content_analysis': {},
            'url_analysis': {},
            'attachment_analysis': {},
            'dns_analysis': {},
            'api_checks': {},
            'verdict': 'unknown',
            'score': 0,
            'indicators': []
        }
        
        # Parse email
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract and analyze headers
        results['headers'] = self.extract_headers(msg)
        header_indicators = self.analyze_headers(results['headers'])
        results['indicators'].extend(header_indicators)
        
        # Perform DNS checks
        from_email = results['headers'].get('From', '')
        results['dns_analysis'] = self.api_dns_integrator.perform_dns_checks(from_email)
        
        # Extract and analyze content
        content = self.extract_content(msg)
        content_indicators = self.analyze_content(content)
        results['content_analysis'] = {
            'indicators': content_indicators,
            'content_preview': content[:500] + '...' if len(content) > 500 else content
        }
        results['indicators'].extend(content_indicators)
        
        # Extract and analyze URLs
        urls = self.extract_urls(content)
        url_analysis = self.analyze_urls(urls)
        results['url_analysis'] = {
            'urls': urls,
            'suspicious_urls': url_analysis,
            'count': len(urls),
            'suspicious_count': len(url_analysis)
        }
        for url, reasons in url_analysis.items():
            results['indicators'].extend([f"URL: {url} - {reason}" for reason in reasons])
        
        # Perform API URL checks
        results['api_checks']['urls'] = self.api_dns_integrator.perform_url_checks(filepath)
        
        # Extract and analyze attachments
        attachments = self.extract_attachments(msg)
        attachment_analysis = self.analyze_attachments(attachments)
        results['attachment_analysis'] = {
            'attachments': [name for name, _ in attachments],
            'suspicious_attachments': attachment_analysis,
            'count': len(attachments),
            'suspicious_count': len(attachment_analysis)
        }
        for filename, reasons in attachment_analysis.items():
            results['indicators'].extend([f"Attachment: {filename} - {reason}" for reason in reasons])
        
        # Perform API attachment checks
        results['api_checks']['attachments'] = self.api_dns_integrator.perform_attachment_checks(filepath)
        
        # Add DNS results to indicators if they're problematic
        dns_indicators = self.analyze_dns_results(results['dns_analysis'])
        results['indicators'].extend(dns_indicators)
        
        # Calculate verdict and score
        results['score'] = self.calculate_score(results['indicators'])
        results['verdict'] = self.determine_verdict(results['score'], len(results['indicators']))
        
        return results
    
    def analyze_dns_results(self, dns_analysis):
        """Analyze DNS results and add to indicators if problematic"""
        indicators = []
        
        if not dns_analysis:
            return indicators
        
        if dns_analysis.get('spf', {}).get('icon') == '❌':
            spf_result = dns_analysis['spf']['result']
            if 'does not exist' in spf_result or 'failed' in spf_result:
                indicators.append(f"DNS: {spf_result}")
            
        if dns_analysis.get('dmarc', {}).get('icon') == '❌':
            dmarc_result = dns_analysis['dmarc']['result']
            if 'does not exist' in dmarc_result or 'failed' in dmarc_result:
                indicators.append(f"DNS: {dmarc_result}")
            
        if dns_analysis.get('dkim', {}).get('icon') == '❌':
            dkim_result = dns_analysis['dkim']['result']
            if 'does not exist' in dkim_result or 'failed' in dkim_result:
                indicators.append(f"DNS: {dkim_result}")
        
        domain = dns_analysis.get('domain', '')
        if domain and not any(trusted in domain for trusted in ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']):
            if dns_analysis.get('spf', {}).get('icon') == '⚠️':
                indicators.append(f"DNS: {dns_analysis['spf']['result']}")
            if dns_analysis.get('dmarc', {}).get('icon') == '⚠️':
                indicators.append(f"DNS: {dns_analysis['dmarc']['result']}")
        
        return indicators
    
    def extract_headers(self, msg):
        """Extract and parse email headers"""
        headers = {}
        for key, value in msg.items():
            headers[key] = value
        return headers
    
    def extract_content(self, msg):
        """Extract text content from email"""
        content = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        content += part.get_content() + "\n"
                    except:
                        continue
        else:
            try:
                content = msg.get_content()
            except:
                content = ""
        return content
    
    def extract_urls(self, content):
        """Extract URLs from email content"""
        # Improved URL regex to catch more patterns
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, content)
        return list(set(urls))
    
    def extract_attachments(self, msg):
        """Extract attachments from email"""
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                if filename and content:
                    attachments.append((filename, content))
        return attachments
    
    def analyze_headers(self, headers):
        """Analyze email headers for suspicious patterns"""
        indicators = []
        
        # Check for spoofed From address
        from_header = headers.get('From', '')
        from_domain = self.extract_domain_from_email(from_header)
        
        return_path = headers.get('Return-Path', '')
        return_path_domain = self.extract_domain_from_email(return_path)
        
        # Only flag if domains are completely different, not subdomains
        if (from_domain and return_path_domain and 
            from_domain != return_path_domain and
            not return_path_domain.endswith(from_domain) and
            not from_domain.endswith(return_path_domain)):
            indicators.append(f"From domain ({from_domain}) differs from Return-Path ({return_path_domain})")
        
        # Check Reply-To header
        reply_to = headers.get('Reply-To', '')
        reply_to_domain = self.extract_domain_from_email(reply_to)
        if (from_domain and reply_to_domain and 
            from_domain != reply_to_domain and
            not reply_to_domain.endswith(from_domain) and
            not from_domain.endswith(reply_to_domain)):
            indicators.append(f"From domain ({from_domain}) differs from Reply-To ({reply_to_domain})")
        
        # Check authentication headers
        auth_results = headers.get('Authentication-Results', '').lower()
        if auth_results:
            if "spf=fail" in auth_results or "spf=softfail" in auth_results:
                indicators.append("SPF authentication failed")
            if "dkim=fail" in auth_results:
                indicators.append("DKIM authentication failed")
            if "dmarc=fail" in auth_results:
                indicators.append("DMARC authentication failed")
        else:
            # Only flag missing authentication headers for external emails
            trusted_domains = getattr(self.config, 'TRUSTED_DOMAINS', []) if hasattr(self.config, 'TRUSTED_DOMAINS') else self.config.get('TRUSTED_DOMAINS', [])
            if from_domain and not any(trusted_domain in from_domain for trusted_domain in trusted_domains):
                indicators.append("No authentication headers found")
        
        # Check for suspicious priority headers
        priority = headers.get('X-Priority', '')
        if priority and priority in ['1', '2']:
            indicators.append("Email marked as high priority (common in phishing)")
        
        return indicators
    
    def analyze_content(self, content):
        """Analyze email content for phishing indicators"""
        indicators = []
        content_lower = content.lower()
        
        suspicious_keywords = getattr(self.config, 'SUSPICIOUS_KEYWORDS', []) if hasattr(self.config, 'SUSPICIOUS_KEYWORDS') else self.config.get('SUSPICIOUS_KEYWORDS', [])
        
        # Check for urgency - only flag if multiple urgency indicators are present
        urgency_count = sum(1 for keyword in suspicious_keywords if keyword in content_lower)
        if urgency_count >= 3:  # Require at least 3 urgency indicators
            indicators.append("Creates artificial urgency")
        
        # Check for sensitive information requests
        sensitive_keywords = ["password", "credit card", "social security", "ssn", 
                            "bank account", "username", "login", "credentials",
                            "account number", "pin", "security code"]
        sensitive_count = sum(1 for keyword in sensitive_keywords if keyword in content_lower)
        if sensitive_count >= 2:  # Require at least 2 sensitive information requests
            indicators.append("Requests sensitive information")
        
        # Check for poor grammar - be more strict
        grammar_errors = ["kindly", "re:", "fw:", "congratulations", "lottery",
                        "inheritance", "prize", "dear customer", "dear user",
                        "dear member", "dear account holder", "urgent action required"]
        error_count = sum(1 for error in grammar_errors if error in content_lower)
        if error_count >= 3:  # Require at least 3 grammar errors
            indicators.append("Contains grammatical errors common in phishing")
        
        # Check for generic greetings
        generic_greetings = ["dear customer", "dear user", "dear member", "dear account holder"]
        if any(greeting in content_lower for greeting in generic_greetings):
            # Only flag if combined with other suspicious elements
            if urgency_count > 0 or sensitive_count > 0:
                indicators.append("Uses generic greeting instead of personal name")
        
        return indicators
    
    def analyze_urls(self, urls):
        """Analyze URLs for phishing indicators"""
        suspicious_urls = {}
        
        for url in urls:
            if self.is_whitelisted(url, "url"):
                continue
                
            reasons = []
            domain = self.extract_domain_from_url(url)
            
            # Check for URL shortening services
            shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly"]
            if any(shortener in domain for shortener in shorteners):
                reasons.append("Uses URL shortening service")
            
            # Check for suspicious keywords in URL - only for non-image URLs
            if not any(ext in url for ext in ['.png', '.jpg', '.jpeg', '.gif', '.css', '.woff']):
                suspicious_keywords = ["login", "verify", "secure", "account", "paypal",
                                    "bank", "password", "update", "confirm"]
                if any(keyword in url.lower() for keyword in suspicious_keywords):
                    reasons.append("Contains sensitive keywords in URL")
            
            # Check for IP addresses in URL - only flag if not a private IP
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', url)
            if ip_match:
                try:
                    ip = ipaddress.ip_address(ip_match.group())
                    if not ip.is_private:
                        reasons.append("Uses IP address instead of domain name")
                except:
                    reasons.append("Uses IP address instead of domain name")
            
            # Check for hex encoding - only flag if excessive encoding
            hex_matches = re.findall(r'%[0-9a-fA-F]{2}', url)
            if len(hex_matches) > 5:  # Only flag if more than 5 encoded characters
                reasons.append("Contains excessive URL-encoded characters (possible obfuscation)")
            
            trusted_domains = getattr(self.config, 'TRUSTED_DOMAINS', []) if hasattr(self.config, 'TRUSTED_DOMAINS') else self.config.get('TRUSTED_DOMAINS', [])
            for trusted_domain in trusted_domains:
                if self.is_domain_impersonating(domain, trusted_domain):
                    reasons.append(f"Possible impersonation of {trusted_domain}")
                    break
            
            if reasons:
                suspicious_urls[url] = reasons
        
        return suspicious_urls
    
    def analyze_attachments(self, attachments):
        """Analyze attachments for suspicious characteristics"""
        suspicious_attachments = {}
        
        for filename, content in attachments:
            if self.is_whitelisted(filename, "filename"):
                continue
                
            reasons = []
            
            dangerous_extensions = getattr(self.config, 'DANGEROUS_EXTENSIONS', []) if hasattr(self.config, 'DANGEROUS_EXTENSIONS') else self.config.get('DANGEROUS_EXTENSIONS', [])
            if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
                reasons.append("Dangerous file type")
            
            if len(content) < 1024:  # Less than 1KB
                reasons.append("Unusually small file")
            elif len(content) > 10 * 1024 * 1024:  # More than 10MB
                reasons.append("Unusually large file")
            
            if re.search(r'\.[a-z]{3,4}\.[a-z]{2,4}$', filename.lower()):
                reasons.append("Double file extension (possible obfuscation)")
            
            suspicious_patterns = [
                b"CreateObject", b"ShellExecute", b"PowerShell", b"regsvr32",
                b"cmd.exe", b"WScript.Shell", b"eval(", b"document.write"
            ]
            for pattern in suspicious_patterns:
                if pattern in content:
                    reasons.append("Contains suspicious code patterns")
                    break
            
            if reasons:
                suspicious_attachments[filename] = reasons
        
        return suspicious_attachments
    
    def extract_domain_from_email(self, email_addr):
        """Extract domain from email address"""
        if not email_addr:
            return None
        try:
            match = re.search(r'<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?', email_addr)
            if match:
                return match.group(1).split('@')[1].lower()
            return None
        except:
            return None
    
    def extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain and parsed.path:
                # Handle URLs without scheme
                domain = parsed.path.split('/')[0]
            return domain.lower()
        except:
            return ""
    
    def is_domain_impersonating(self, domain, trusted_domain):
        """Check if a domain is impersonating a trusted domain"""
        domain = domain.replace('www.', '')
        trusted_domain = trusted_domain.replace('www.', '')
        
        if domain == trusted_domain:
            return False
        
        if trusted_domain in domain:
            if domain.endswith('.' + trusted_domain):
                return False
            
            diff = len(domain) - len(trusted_domain)
            if diff <= 4 and not domain.startswith(trusted_domain + '.'):
                return True
        
        if len(domain) == len(trusted_domain):
            diff_count = sum(1 for a, b in zip(domain, trusted_domain) if a != b)
            if diff_count <= 2:  # Allow up to 2 character differences
                return True
        
        homograph_pairs = [('rn', 'm'), ('cl', 'd'), ('vv', 'w'), ('ci', 'a')]
        for original, replacement in homograph_pairs:
            if replacement in trusted_domain and original in domain:
                modified_trusted = trusted_domain.replace(replacement, original)
                if domain == modified_trusted:
                    return True
        
        if trusted_domain.replace('-', '') == domain.replace('-', ''):
            return True
        
        return False
    
    def is_whitelisted(self, value, data_type):
        """Check if a value is whitelisted"""
        if value in self.whitelist["exactMatching"].get(data_type, []):
            return True
        
        for pattern in self.whitelist["regexMatching"].get(data_type, []):
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        if data_type in ["url", "domain"]:
            domain = self.extract_domain_from_url(value) if data_type == "url" else value
            for whitelist_domain in self.whitelist["domainsInSubdomains"]:
                if domain.endswith(whitelist_domain) or whitelist_domain in domain:
                    return True
        
        return False
    
    def calculate_score(self, indicators):
        """Calculate phishing probability score based on detected indicators"""
        if not indicators:
            return 0.0
        
        indicator_weights = {
            "header": 0.25,
            "url": 0.20, 
            "content": 0.15,
            "attachment": 0.15,
            "authentication": 0.15,
            "dns": 0.10  # Added DNS weight
        }
        
        category_scores = {
            "header": 0,
            "url": 0,
            "content": 0,
            "attachment": 0,
            "authentication": 0,
            "dns": 0
        }
        
        category_counts = {
            "header": 0,
            "url": 0,
            "content": 0,
            "attachment": 0,
            "authentication": 0,
            "dns": 0
        }
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            
            if any(keyword in indicator_lower for keyword in ["header", "from", "received", "reply-to", "return-path"]):
                category = "header"
            elif any(keyword in indicator_lower for keyword in ["url", "http", "www", "link"]):
                category = "url"
            elif any(keyword in indicator_lower for keyword in ["content", "urgent", "sensitive", "grammar", "greeting"]):
                category = "content"
            elif any(keyword in indicator_lower for keyword in ["attachment", "file", "extension"]):
                category = "attachment"
            elif any(keyword in indicator_lower for keyword in ["authentication", "spf", "dkim", "dmarc"]):
                category = "authentication"
            elif any(keyword in indicator_lower for keyword in ["dns"]):
                category = "dns"
            else:
                category = "header"
            
            category_counts[category] += 1
        
        for category, count in category_counts.items():
            if count > 0:
                category_score = min(count / 3, 1.0) * indicator_weights[category]
                category_scores[category] = category_score
        
        total_score = sum(category_scores.values())
        
        active_categories = sum(1 for score in category_scores.values() if score > 0)
        if active_categories > 1:
            total_score = min(1.0, total_score * (1 + (active_categories - 1) * 0.1))
        
        return min(total_score, 1.0)
    
    def determine_verdict(self, score, indicator_count):
        """Determine final verdict based on score and indicator count"""
        if score > 0.7 and indicator_count >= 3:
            return "malicious"
        elif score > 0.4 or indicator_count >= 2:
            return "suspicious"
        else:
            return "clean"
