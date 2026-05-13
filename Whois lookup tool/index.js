#!/usr/bin/env node

const whois = require('whois');
const { program } = require('commander');
const fs = require('fs').promises;
const util = require('util');

class WhoisLookup {
    constructor(domain, timeout = 10000) {
        this.domain = domain.toLowerCase().trim();
        this.timeout = timeout;
        this.data = {};
    }
    
    parseWhoisData(rawData) {
        const data = {};
        const lines = rawData.split('\n');
        
        for (const line of lines) {
            if (line.includes(':')) {
                const [key, ...valueParts] = line.split(':');
                const cleanKey = key.trim().toLowerCase().replace(/\s+/g, '_');
                let value = valueParts.join(':').trim();
                
                // Handle dates
                if (value && (cleanKey.includes('date') || cleanKey.includes('updated'))) {
                    value = this.parseDate(value);
                }
                
                // Handle lists
                if (cleanKey === 'name_server' || cleanKey === 'nserver') {
                    if (!data.name_servers) data.name_servers = [];
                    data.name_servers.push(value);
                } else if (cleanKey === 'status') {
                    if (!data.status) data.status = [];
                    data.status.push(value);
                } else {
                    data[cleanKey] = value;
                }
            }
        }
        
        // Clean up
        if (data.name_servers) {
            data.name_servers = [...new Set(data.name_servers)];
        }
        
        return data;
    }
    
    parseDate(dateStr) {
        try {
            const date = new Date(dateStr);
            if (!isNaN(date.getTime())) {
                return date.toISOString().split('T')[0];
            }
        } catch(e) {}
        return dateStr;
    }
    
    async lookup() {
        return new Promise((resolve, reject) => {
            whois.lookup(this.domain, { timeout: this.timeout }, (err, rawData) => {
                if (err) {
                    reject(new Error(`WHOIS lookup failed: ${err.message}`));
                } else {
                    try {
                        this.data = this.parseWhoisData(rawData);
                        resolve(this.data);
                    } catch (parseErr) {
                        reject(new Error(`Failed to parse WHOIS data: ${parseErr.message}`));
                    }
                }
            });
        });
    }
    
    getSummary() {
        return {
            domain: this.domain,
            registrar: this.data.registrar || this.data.registrar_name,
            creation_date: this.data.creation_date || this.data.created_date,
            expiration_date: this.data.expiration_date || this.data.registry_expiry_date,
            name_servers: (this.data.name_servers || []).slice(0, 3),
            registrant_org: this.data.org || this.data.registrant_organization,
            status: (this.data.status || []).slice(0, 2)
        };
    }
    
    isExpiringSoon(days = 30) {
        const expDate = this.data.expiration_date || this.data.registry_expiry_date;
        if (!expDate) return false;
        
        try {
            const exp = new Date(expDate);
            const now = new Date();
            const daysLeft = Math.floor((exp - now) / (1000 * 60 * 60 * 24));
            return daysLeft >= 0 && daysLeft <= days;
        } catch(e) {
            return false;
        }
    }
    
    printResults(verbose = false) {
        console.log(`\n${'='.repeat(60)}`);
        console.log(`WHOIS Lookup Results for: ${this.domain}`);
        console.log(`${'='.repeat(60)}\n`);
        
        if (verbose) {
            console.log(JSON.stringify(this.data, null, 2));
        } else {
            const summary = this.getSummary();
            console.log(`Registrar:        ${summary.registrar || 'N/A'}`);
            console.log(`Created:          ${summary.creation_date || 'N/A'}`);
            console.log(`Expires:          ${summary.expiration_date || 'N/A'}`);
            console.log(`Name Servers:     ${summary.name_servers.join(', ') || 'N/A'}`);
            console.log(`Registrant Org:   ${summary.registrant_org || 'N/A'}`);
            console.log(`Status:           ${summary.status.join(', ') || 'N/A'}`);
            
            if (this.isExpiringSoon()) {
                console.log(`\n⚠️  WARNING: Domain expires within 30 days!`);
            }
        }
        
        console.log(`\n${'='.repeat(60)}\n`);
    }
}

// CLI Interface
program
    .requiredOption('-d, --domain <domain>', 'Domain name to lookup')
    .option('-v, --verbose', 'Show detailed information')
    .option('-j, --json', 'Output as JSON')
    .option('-s, --summary', 'Show summary only')
    .option('-t, --timeout <ms>', 'Timeout in milliseconds', 10000)
    .option('-o, --output <file>', 'Output file to save results')
    .parse(process.argv);

const options = program.opts();

async function main() {
    try {
        const lookup = new WhoisLookup(options.domain, options.timeout);
        await lookup.lookup();
        
        let outputData = '';
        
        if (options.json) {
            outputData = JSON.stringify(lookup.data, null, 2);
            console.log(outputData);
        } else if (options.summary) {
            outputData = JSON.stringify(lookup.getSummary(), null, 2);
            console.log(outputData);
        } else {
            lookup.printResults(options.verbose);
            outputData = JSON.stringify(lookup.data, null, 2);
        }
        
        if (options.output) {
            await fs.writeFile(options.output, outputData);
            console.log(`\n[+] Results saved to ${options.output}`);
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

main();
