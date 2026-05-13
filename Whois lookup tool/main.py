#!/usr/bin/env python3
"""
Whois Lookup Tool - Fetches domain registration details
"""

import whois
import argparse
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional

class WhoisLookup:
    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.data = {}
    
    def lookup(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            # Query WHOIS server
            w = whois.whois(self.domain)
            
            # Parse and format data
            self.data = {
                'domain_name': self._parse_list(w.domain_name),
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'referral_url': w.referral_url,
                'updated_date': self._format_date(w.updated_date),
                'creation_date': self._format_date(w.creation_date),
                'expiration_date': self._format_date(w.expiration_date),
                'name_servers': self._parse_list(w.name_servers),
                'status': self._parse_list(w.status),
                'emails': self._parse_list(w.emails),
                'dnssec': w.dnssec,
                'name': w.name,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country,
                'phone': self._parse_list(w.phone),
                'fax': self._parse_list(w.fax),
            }
            
            return self.data
            
        except Exception as e:
            raise Exception(f"WHOIS lookup failed for {self.domain}: {str(e)}")
    
    def _parse_list(self, value):
        """Parse list values"""
        if isinstance(value, list):
            return [str(v) for v in value if v]
        return value if value else None
    
    def _format_date(self, date_value):
        """Format date fields"""
        if isinstance(date_value, list):
            return [d.strftime('%Y-%m-%d %H:%M:%S') if d else None for d in date_value]
        elif date_value:
            return date_value.strftime('%Y-%m-%d %H:%M:%S')
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summarized information"""
        summary = {
            'domain': self.domain,
            'registrar': self.data.get('registrar'),
            'creation_date': self.data.get('creation_date'),
            'expiration_date': self.data.get('expiration_date'),
            'name_servers': self.data.get('name_servers', [])[:3],  # First 3 NS
            'registrant_org': self.data.get('org'),
            'status': self.data.get('status', [])[:2]  # First 2 statuses
        }
        return summary
    
    def is_expiring_soon(self, days: int = 30) -> bool:
        """Check if domain expires within specified days"""
        exp_date = self.data.get('expiration_date')
        if exp_date and isinstance(exp_date, str):
            try:
                exp = datetime.strptime(exp_date, '%Y-%m-%d %H:%M:%S')
                days_left = (exp - datetime.now()).days
                return 0 <= days_left <= days
            except:
                pass
        return False
    
    def to_json(self, pretty: bool = True) -> str:
        """Convert results to JSON"""
        indent = 2 if pretty else None
        return json.dumps(self.data, indent=indent, default=str)
    
    def print_results(self, verbose: bool = False):
        """Print formatted results"""
        print(f"\n{'='*60}")
        print(f"WHOIS Lookup Results for: {self.domain}")
        print(f"{'='*60}\n")
        
        if verbose:
            # Detailed output
            for key, value in self.data.items():
                if value:
                    key_display = key.replace('_', ' ').title()
                    if isinstance(value, list):
                        print(f"{key_display}:")
                        for item in value:
                            print(f"  - {item}")
                    else:
                        print(f"{key_display}: {value}")
        else:
            # Summary output
            summary = self.get_summary()
            print(f"Registrar:        {summary.get('registrar', 'N/A')}")
            print(f"Created:          {summary.get('creation_date', 'N/A')}")
            print(f"Expires:          {summary.get('expiration_date', 'N/A')}")
            print(f"Name Servers:     {', '.join(summary.get('name_servers', ['N/A']))}")
            print(f"Registrant Org:   {summary.get('registrant_org', 'N/A')}")
            print(f"Status:           {', '.join(summary.get('status', ['N/A']))}")
            
            if self.is_expiring_soon():
                print(f"\n⚠️  WARNING: Domain expires within 30 days!")
        
        print(f"\n{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(description='WHOIS Lookup Tool')
    parser.add_argument('-d', '--domain', required=True, help='Domain name to lookup')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed information')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--summary', action='store_true', help='Show summary only')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file to save results')
    
    args = parser.parse_args()
    
    try:
        # Perform lookup
        lookup = WhoisLookup(args.domain, args.timeout)
        data = lookup.lookup()
        
        # Output format
        if args.json:
            output = lookup.to_json()
            print(output)
        elif args.summary:
            print(json.dumps(lookup.get_summary(), indent=2))
        else:
            lookup.print_results(verbose=args.verbose)
        
        # Save to file
        if args.output:
            with open(args.output, 'w') as f:
                if args.json:
                    f.write(output)
                else:
                    f.write(json.dumps(data, indent=2, default=str))
            print(f"\n[+] Results saved to {args.output}")
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
