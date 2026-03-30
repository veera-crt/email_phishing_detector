import dns.resolver
import requests
import re
from email import policy
from email.parser import BytesParser
import hashlib
from urllib.parse import urlparse
from config import Config


class APIDNSIntegrator:
    def __init__(self, config):
        self.config = config
        if isinstance(config, dict):
            self.vt_api_key = config.get('VIRUSTOTAL_API_KEY') or Config.VIRUSTOTAL_API_KEY
            self.enable_vt = config.get('ENABLE_VIRUSTOTAL', Config.ENABLE_VIRUSTOTAL)
        else:
            self.vt_api_key = config.VIRUSTOTAL_API_KEY
            self.enable_vt = config.ENABLE_VIRUSTOTAL

    def get_domain_from_email(self, email_addr):
        try:
            return email_addr.split('@')[1]
        except:
            return None

    def check_spf(self, domain):
        try:
            answers = dns.resolver.resolve(f"{domain}", "TXT", lifetime=10)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if 'v=spf1' in txt_record:
                    return "SPF record found", "✅"
            return "No SPF record found", "⚠️"
        except dns.resolver.NXDOMAIN:
            return "Domain does not exist", "❌"
        except dns.resolver.NoAnswer:
            return "No SPF record found", "⚠️"
        except dns.resolver.Timeout:
            return "DNS timeout - unable to check SPF", "⚪"
        except Exception as e:
            return f"SPF check error: DNS resolution failed", "⚪"

    def check_dmarc(self, domain):
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=10)
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if 'v=DMARC1' in txt_record:
                    return "DMARC record found", "✅"
            return "No DMARC record found", "⚠️"
        except dns.resolver.NXDOMAIN:
            return "No DMARC record found", "⚠️"
        except dns.resolver.NoAnswer:
            return "No DMARC record found", "⚠️"
        except dns.resolver.Timeout:
            return "DNS timeout - unable to check DMARC", "⚪"
        except Exception as e:
            return f"DMARC check error: DNS resolution failed", "⚪"

    def check_dkim(self, domain):
        common_selectors = ['default', 'google', 'selector1', 'selector2', 'dkim', 'mail', 'k1']
        
        for selector in common_selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=10)
                for rdata in answers:
                    txt_record = str(rdata).strip('"')
                    if 'v=DKIM1' in txt_record or 'k=' in txt_record:
                        return f"DKIM record found (selector: {selector})", "✅"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.Timeout:
                return "DNS timeout - unable to check DKIM", "⚪"
            except Exception:
                continue
        
        return "No DKIM record found", "⚠️"

    def extract_urls_from_email(self, filepath):
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        urls = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    text = part.get_content()
                    urls += re.findall(r'https?://[^\s]+', text)
        else:
            text = msg.get_content()
            urls += re.findall(r'https?://[^\s]+', text)

        return list(set(urls))

    def scan_url_virustotal(self, url):
        if not self.enable_vt:
            return "VirusTotal scanning disabled", "⚪"
            
        headers = {"x-apikey": self.vt_api_key}
        vt_url = "https://www.virustotal.com/api/v3/urls"
        
        try:
            response = requests.post(vt_url, headers=headers, data={"url": url})
            if response.status_code == 200:
                analysis_id = response.json()['data']['id']
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                
                # Wait a moment for analysis to complete
                import time
                time.sleep(2)
                
                analysis = requests.get(analysis_url, headers=headers)
                if analysis.status_code == 200:
                    stats = analysis.json()['data']['attributes']['stats']
                    if stats.get('malicious', 0) > 0:
                        return f"Malicious ({stats['malicious']} engines)", "❌"
                    elif stats.get('suspicious', 0) > 0:
                        return f"Suspicious ({stats['suspicious']} engines)", "⚠️"
                    else:
                        return "Clean", "✅"
            return "Scan failed", "⚪"
        except Exception as e:
            return f"Error: {str(e)}", "⚪"

    def extract_attachments(self, filepath):
        attachments = []
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                if filename and content:
                    attachments.append((filename, content))
        return attachments

    def get_file_hash(self, content):
        return hashlib.sha256(content).hexdigest()

    def scan_attachment_vt(self, sha256_hash):
        if not self.enable_vt:
            return "VirusTotal scanning disabled", "⚪"
            
        headers = {"x-apikey": self.vt_api_key}
        vt_file_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        
        try:
            response = requests.get(vt_file_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    return f"Malicious ({stats['malicious']} engines)", "❌"
                elif stats.get('suspicious', 0) > 0:
                    return f"Suspicious ({stats['suspicious']} engines)", "⚠️"
                else:
                    return "Clean", "✅"
            elif response.status_code == 404:
                return "Not found in VirusTotal", "⚪"
            else:
                return "Error retrieving data", "⚪"
        except Exception as e:
            return f"Error: {str(e)}", "⚪"

    def perform_dns_checks(self, from_email):
        domain = self.get_domain_from_email(from_email)
        if not domain:
            return {
                'spf': {'result': 'No sender domain found', 'icon': '⚪'},
                'dmarc': {'result': 'No sender domain found', 'icon': '⚪'},
                'dkim': {'result': 'No sender domain found', 'icon': '⚪'},
                'domain': 'Unknown'
            }
        
        if not self.is_valid_domain(domain):
            return {
                'spf': {'result': 'Invalid domain format', 'icon': '⚪'},
                'dmarc': {'result': 'Invalid domain format', 'icon': '⚪'},
                'dkim': {'result': 'Invalid domain format', 'icon': '⚪'},
                'domain': domain
            }
        
        spf_result, spf_icon = self.check_spf(domain)
        dmarc_result, dmarc_icon = self.check_dmarc(domain)
        dkim_result, dkim_icon = self.check_dkim(domain)
        
        return {
            'spf': {'result': spf_result, 'icon': spf_icon},
            'dmarc': {'result': dmarc_result, 'icon': dmarc_icon},
            'dkim': {'result': dkim_result, 'icon': dkim_icon},
            'domain': domain
        }

    def perform_url_checks(self, filepath):
        urls = self.extract_urls_from_email(filepath)
        url_results = {}
        
        for url in urls[:10]:  # Limit to first 10 URLs to avoid rate limits
            result, icon = self.scan_url_virustotal(url)
            url_results[url] = {'result': result, 'icon': icon}
            
        return url_results

    def perform_attachment_checks(self, filepath):
        attachments = self.extract_attachments(filepath)
        attachment_results = {}
        
        for filename, content in attachments:
            file_hash = self.get_file_hash(content)
            result, icon = self.scan_attachment_vt(file_hash)
            attachment_results[filename] = {
                'hash': file_hash,
                'result': result,
                'icon': icon,
                'size': len(content)
            }
            
        return attachment_results

    def is_valid_domain(self, domain):
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(domain_pattern, domain) is not None and len(domain) <= 253
