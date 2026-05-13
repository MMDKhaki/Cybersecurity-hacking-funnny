#!/usr/bin/env python3
"""
Subdomain Enumerator - DNS brute-forcing + External APIs
"""

import dns.resolver
import requests
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 50, api_keys: dict = None):
        self.domain = domain
        self.threads = threads
        self.api_keys = api_keys or {}
        self.subdomains: Set[str] = set()
        
    def load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load subdomain wordlist"""
        default_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
            'dashboard', 'portal', 'manage', 'start', 'info', 'apps', 'video', 'sip',
            'dns2', 'api', 'cdn', 'mssql', 'remote', 'server', 'ftp2', 'stage', 'vps'
        ]
        
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"Wordlist not found, using default")
        return default_wordlist
    
    def brute_force_dns(self, subdomain: str) -> bool:
        """Brute force DNS query for a subdomain"""
        target = f"{subdomain}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(target, 'A')
            if answers:
                ip = answers[0].to_text()
                print(f"[DNS] Found: {target} -> {ip}")
                self.subdomains.add(target)
                return True
        except:
            pass
        return False
    
    def api_securitytrails(self) -> Set[str]:
        """Query SecurityTrails API"""
        if not self.api_keys.get('securitytrails'):
            return set()
        
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {'APIKEY': self.api_keys['securitytrails']}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = [f"{sub}.{self.domain}" for sub in data.get('subdomains', [])]
                for sub in subdomains:
                    print(f"[SecurityTrails] Found: {sub}")
                return set(subdomains)
        except Exception as e:
            print(f"SecurityTrails API error: {e}")
        return set()
    
    def api_virustotal(self) -> Set[str]:
        """Query VirusTotal API"""
        if not self.api_keys.get('virustotal'):
            return set()
        
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = []
                for item in data.get('data', []):
                    sub = item.get('id', '')
                    if sub.endswith(self.domain):
                        subdomains.append(sub)
                        print(f"[VirusTotal] Found: {sub}")
                return set(subdomains)
        except Exception as e:
            print(f"VirusTotal API error: {e}")
        return set()
    
    def api_censys(self) -> Set[str]:
        """Query Censys API (simplified)"""
        if not self.api_keys.get('censys'):
            return set()
        
        # Censys v2 API requires more complex auth
        print("[Censys] API integration requires additional setup")
        return set()
    
    def enumerate(self, wordlist_path: str = None):
        """Main enumeration function"""
        print(f"[*] Starting subdomain enumeration for: {self.domain}")
        print(f"[*] Using {self.threads} threads")
        
        # Load wordlist
        wordlist = self.load_wordlist(wordlist_path)
        print(f"[*] Loaded {len(wordlist)} subdomain candidates")
        
        # API enumeration
        print("\n[*] Querying external APIs...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            api_futures = [
                executor.submit(self.api_securitytrails),
                executor.submit(self.api_virustotal),
                executor.submit(self.api_censys)
            ]
            
            for future in as_completed(api_futures):
                self.subdomains.update(future.result())
        
        # DNS brute-force
        print(f"\n[*] DNS brute-force in progress...")
        found_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {executor.submit(self.brute_force_dns, sub): sub for sub in wordlist}
            
            for future in as_completed(future_to_sub):
                if future.result():
                    found_count += 1
        
        # Results
        print(f"\n[+] Enumeration complete! Found {len(self.subdomains)} unique subdomains")
        if self.subdomains:
            print("\n[+] Subdomains found:")
            for sub in sorted(self.subdomains):
                print(f"  - {sub}")

def main():
    parser = argparse.ArgumentParser(description='Subdomain Enumerator')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--st-api', help='SecurityTrails API key')
    parser.add_argument('--vt-api', help='VirusTotal API key')
    
    args = parser.parse_args()
    
    api_keys = {
        'securitytrails': args.st_api,
        'virustotal': args.vt_api
    }
    
    enumerator = SubdomainEnumerator(args.domain, args.threads, api_keys)
    enumerator.enumerate(args.wordlist)

if __name__ == "__main__":
    main()
