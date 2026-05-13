## Usage Examples

### Python
```bash
# Basic usage
python3 subdomain_enum.py -d example.com

# With custom wordlist and threads
python3 subdomain_enum.py -d example.com -w subdomains.txt -t 100

# With APIs
python3 subdomain_enum.py -d example.com --st-api YOUR_KEY --vt-api YOUR_KEY
```

### Go
```bash
# Build
go build subdomain_enum.go

# Run
./subdomain_enum -d example.com
./subdomain_enum -d example.com -w wordlist.txt -t 100
```

### Node.js
```bash
# Install dependencies
npm install commander

# Run
node subdomain_enum.js -d example.com
node subdomain_enum.js -d example.com -w wordlist.txt -t 100
```

### Bash
```bash
# Make executable
chmod +x subdomain_enum.sh

# Run
./subdomain_enum.sh -d example.com
./subdomain_enum.sh -d example.com -w wordlist.txt -t 100

# With APIs
./subdomain_enum.sh -d example.com --st-api YOUR_KEY --vt-api YOUR_KEY
```

## Key Features Across All Versions

1. **DNS Brute-forcing**: Queries common subdomain names against DNS servers
2. **API Integration**: SecurityTrails, VirusTotal, and Censys (certificate transparency in Bash)
3. **Concurrent Processing**: Multi-threaded/parallel DNS resolution
4. **Custom Wordlists**: Support for user-provided subdomain lists
5. **Result Deduplication**: Ensures unique results across all sources

Each implementation uses native features of its language while maintaining the same core functionality. The Bash version includes additional features like certificate transparency logging (crt.sh) as a bonus.
