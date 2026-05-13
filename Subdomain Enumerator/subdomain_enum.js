#!/usr/bin/env node

const dns = require('dns').promises;
const https = require('https');
const fs = require('fs');
const { program } = require('commander');

class SubdomainEnumerator {
    constructor(domain, threads = 50, apiKeys = {}) {
        this.domain = domain;
        this.threads = threads;
        this.apiKeys = apiKeys;
        this.subdomains = new Set();
    }

    loadWordlist(wordlistPath = null) {
        const defaultWordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'api', 'cdn', 'stage', 'secure', 'portal'
        ];

        if (wordlistPath) {
            try {
                const content = fs.readFileSync(wordlistPath, 'utf8');
                return content.split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#'));
            } catch (err) {
                console.log(`Wordlist not found, using default`);
            }
        }
        return defaultWordlist;
    }

    async bruteForceDNS(subdomain) {
        const target = `${subdomain}.${this.domain}`;
        try {
            const resolver = new dns.Resolver();
            resolver.setServers(['8.8.8.8', '1.1.1.1']);
            const addresses = await resolver.resolve4(target);
            if (addresses && addresses.length > 0) {
                console.log(`[DNS] Found: ${target} -> ${addresses[0]}`);
                this.subdomains.add(target);
                return true;
            }
        } catch (err) {
            // Subdomain not found
        }
        return false;
    }

    async apiSecurityTrails() {
        if (!this.apiKeys.securitytrails) return;

        const options = {
            hostname: 'api.securitytrails.com',
            path: `/v1/domain/${this.domain}/subdomains`,
            headers: { 'APIKEY': this.apiKeys.securitytrails },
            timeout: 10000
        };

        return new Promise((resolve) => {
            https.get(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const json = JSON.parse(data);
                            json.subdomains?.forEach(sub => {
                                const full = `${sub}.${this.domain}`;
                                console.log(`[SecurityTrails] Found: ${full}`);
                                this.subdomains.add(full);
                            });
                        } catch (e) {}
                    }
                    resolve();
                });
            }).on('error', () => resolve());
        });
    }

    async apiVirusTotal() {
        if (!this.apiKeys.virustotal) return;

        const options = {
            hostname: 'www.virustotal.com',
            path: `/api/v3/domains/${this.domain}/subdomains`,
            headers: { 'x-apikey': this.apiKeys.virustotal },
            timeout: 10000
        };

        return new Promise((resolve) => {
            https.get(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const json = JSON.parse(data);
                            json.data?.forEach(item => {
                                if (item.id?.endsWith(this.domain)) {
                                    console.log(`[VirusTotal] Found: ${item.id}`);
                                    this.subdomains.add(item.id);
                                }
                            });
                        } catch (e) {}
                    }
                    resolve();
                });
            }).on('error', () => resolve());
        });
    }

    async enumerate(wordlistPath = null) {
        console.log(`[*] Starting subdomain enumeration for: ${this.domain}`);
        console.log(`[*] Using ${this.threads} threads`);

        const wordlist = this.loadWordlist(wordlistPath);
        console.log(`[*] Loaded ${wordlist.length} subdomain candidates`);

        // API enumeration
        console.log(`\n[*] Querying external APIs...`);
        await Promise.all([
            this.apiSecurityTrails(),
            this.apiVirusTotal()
        ]);

        // DNS brute-force with concurrency control
        console.log(`\n[*] DNS brute-force in progress...`);
        const queue = [...wordlist];
        let active = 0;
        let completed = 0;

        const worker = async () => {
            while (queue.length > 0) {
                const sub = queue.shift();
                await this.bruteForceDNS(sub);
                completed++;
                if (completed % 100 === 0) {
                    process.stdout.write(`\r[*] Progress: ${completed}/${wordlist.length}`);
                }
            }
        };

        const workers = Array(Math.min(this.threads, wordlist.length))
            .fill()
            .map(() => worker());
        
        await Promise.all(workers);
        console.log(); // New line after progress

        // Results
        console.log(`\n[+] Enumeration complete! Found ${this.subdomains.size} unique subdomains`);
        if (this.subdomains.size > 0) {
            console.log(`\n[+] Subdomains found:`);
            Array.from(this.subdomains).sort().forEach(sub => {
                console.log(`  - ${sub}`);
            });
        }
    }
}

// CLI interface
program
    .requiredOption('-d, --domain <domain>', 'Target domain')
    .option('-w, --wordlist <path>', 'Custom wordlist file')
    .option('-t, --threads <number>', 'Number of threads', parseInt, 50)
    .option('--st-api <key>', 'SecurityTrails API key')
    .option('--vt-api <key>', 'VirusTotal API key')
    .parse(process.argv);

const options = program.opts();

const apiKeys = {
    securitytrails: options.stApi,
    virustotal: options.vtApi
};

const enumerator = new SubdomainEnumerator(options.domain, options.threads, apiKeys);
enumerator.enumerate(options.wordlist).catch(console.error);
