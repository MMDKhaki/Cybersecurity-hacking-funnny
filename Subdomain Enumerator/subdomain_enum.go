package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type SubdomainEnumerator struct {
	domain    string
	threads   int
	apiKeys   map[string]string
	subdomains map[string]bool
	mu        sync.Mutex
}

type SecurityTrailsResponse struct {
	Subdomains []string `json:"subdomains"`
}

type VirusTotalResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func NewSubdomainEnumerator(domain string, threads int, apiKeys map[string]string) *SubdomainEnumerator {
	return &SubdomainEnumerator{
		domain:     domain,
		threads:    threads,
		apiKeys:    apiKeys,
		subdomains: make(map[string]bool),
	}
}

func (s *SubdomainEnumerator) loadWordlist(path string) ([]string, error) {
	defaultWordlist := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
		"ns2", "cpanel", "whm", "test", "dev", "admin", "blog", "vpn",
		"api", "cdn", "stage", "secure", "portal", "dashboard", "stats",
	}

	if path == "" {
		return defaultWordlist, nil
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Wordlist not found, using default: %v\n", err)
		return defaultWordlist, nil
	}
	defer file.Close()

	var wordlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}
	return wordlist, scanner.Err()
}

func (s *SubdomainEnumerator) bruteForceDNS(subdomain string) bool {
	target := fmt.Sprintf("%s.%s", subdomain, s.domain)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, "ip4", target)
	if err == nil && len(ips) > 0 {
		fmt.Printf("[DNS] Found: %s -> %s\n", target, ips[0].String())
		s.mu.Lock()
		s.subdomains[target] = true
		s.mu.Unlock()
		return true
	}
	return false
}

func (s *SubdomainEnumerator) apiSecurityTrails() {
	if s.apiKeys["securitytrails"] == "" {
		return
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", s.domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("APIKEY", s.apiKeys["securitytrails"])

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("SecurityTrails API error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result SecurityTrailsResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, sub := range result.Subdomains {
				full := fmt.Sprintf("%s.%s", sub, s.domain)
				fmt.Printf("[SecurityTrails] Found: %s\n", full)
				s.mu.Lock()
				s.subdomains[full] = true
				s.mu.Unlock()
			}
		}
	}
}

func (s *SubdomainEnumerator) apiVirusTotal() {
	if s.apiKeys["virustotal"] == "" {
		return
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", s.domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", s.apiKeys["virustotal"])

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("VirusTotal API error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result VirusTotalResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, item := range result.Data {
				if strings.HasSuffix(item.ID, s.domain) {
					fmt.Printf("[VirusTotal] Found: %s\n", item.ID)
					s.mu.Lock()
					s.subdomains[item.ID] = true
					s.mu.Unlock()
				}
			}
		}
	}
}

func (s *SubdomainEnumerator) enumerate(wordlistPath string) {
	fmt.Printf("[*] Starting subdomain enumeration for: %s\n", s.domain)
	fmt.Printf("[*] Using %d threads\n", s.threads)

	wordlist, _ := s.loadWordlist(wordlistPath)
	fmt.Printf("[*] Loaded %d subdomain candidates\n", len(wordlist))

	// API enumeration
	fmt.Println("\n[*] Querying external APIs...")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.apiSecurityTrails() }()
	go func() { defer wg.Done(); s.apiVirusTotal() }()
	wg.Wait()

	// DNS brute-force
	fmt.Printf("\n[*] DNS brute-force in progress...\n")
	semaphore := make(chan struct{}, s.threads)
	var dnsWg sync.WaitGroup

	for _, sub := range wordlist {
		dnsWg.Add(1)
		go func(sub string) {
			defer dnsWg.Done()
			semaphore <- struct{}{}
			s.bruteForceDNS(sub)
			<-semaphore
		}(sub)
	}
	dnsWg.Wait()

	// Results
	fmt.Printf("\n[+] Enumeration complete! Found %d unique subdomains\n", len(s.subdomains))
	if len(s.subdomains) > 0 {
		fmt.Println("\n[+] Subdomains found:")
		for sub := range s.subdomains {
			fmt.Printf("  - %s\n", sub)
		}
	}
}

func main() {
	domain := flag.String("d", "", "Target domain")
	wordlist := flag.String("w", "", "Custom wordlist file")
	threads := flag.Int("t", 50, "Number of threads")
	stAPI := flag.String("st-api", "", "SecurityTrails API key")
	vtAPI := flag.String("vt-api", "", "VirusTotal API key")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Error: Domain is required")
		flag.Usage()
		os.Exit(1)
	}

	apiKeys := map[string]string{
		"securitytrails": *stAPI,
		"virustotal":     *vtAPI,
	}

	enumerator := NewSubdomainEnumerator(*domain, *threads, apiKeys)
	enumerator.enumerate(*wordlist)
}
