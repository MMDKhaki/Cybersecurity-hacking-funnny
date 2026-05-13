package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type WhoisData struct {
	DomainName     interface{}   `json:"domain_name"`
	Registrar      string        `json:"registrar"`
	WhoisServer    string        `json:"whois_server"`
	CreationDate   string        `json:"creation_date"`
	ExpirationDate string        `json:"expiration_date"`
	UpdatedDate    string        `json:"updated_date"`
	NameServers    []string      `json:"name_servers"`
	Status         []string      `json:"status"`
	Emails         []string      `json:"emails"`
	Org            string        `json:"org"`
	Country        string        `json:"country"`
	Phone          string        `json:"phone"`
}

type WhoisLookup struct {
	Domain  string
	Timeout int
	Data    *WhoisData
}

func NewWhoisLookup(domain string, timeout int) *WhoisLookup {
	return &WhoisLookup{
		Domain:  strings.ToLower(strings.TrimSpace(domain)),
		Timeout: timeout,
		Data:    &WhoisData{},
	}
}

func (w *WhoisLookup) Lookup() error {
	// Query WHOIS server
	raw, err := whois.Whois(w.Domain)
	if err != nil {
		return fmt.Errorf("WHOIS query failed: %v", err)
	}
	
	// Parse response
	result, err := whoisparser.Parse(raw)
	if err != nil {
		return fmt.Errorf("WHOIS parsing failed: %v", err)
	}
	
	// Populate data structure
	w.Data.DomainName = result.Domain.Domain
	w.Data.Registrar = result.Registrar.Name
	w.Data.WhoisServer = result.WhoisServer
	
	if result.Domain.CreatedDate != "" {
		w.Data.CreationDate = result.Domain.CreatedDate
	}
	if result.Domain.ExpirationDate != "" {
		w.Data.ExpirationDate = result.Domain.ExpirationDate
	}
	if result.Domain.UpdatedDate != "" {
		w.Data.UpdatedDate = result.Domain.UpdatedDate
	}
	
	// Name servers
	for _, ns := range result.NameServers {
		w.Data.NameServers = append(w.Data.NameServers, ns)
	}
	
	// Status
	for _, status := range result.Domain.Status {
		w.Data.Status = append(w.Data.Status, status)
	}
	
	// Contact information
	if result.Registrant.Email != "" {
		w.Data.Emails = append(w.Data.Emails, result.Registrant.Email)
	}
	w.Data.Org = result.Registrant.Organization
	w.Data.Country = result.Registrant.Country
	w.Data.Phone = result.Registrant.Phone
	
	return nil
}

func (w *WhoisLookup) GetSummary() map[string]interface{} {
	summary := make(map[string]interface{})
	summary["domain"] = w.Domain
	summary["registrar"] = w.Data.Registrar
	summary["creation_date"] = w.Data.CreationDate
	summary["expiration_date"] = w.Data.ExpirationDate
	summary["name_servers"] = w.Data.NameServers
	summary["registrant_org"] = w.Data.Org
	return summary
}

func (w *WhoisLookup) IsExpiringSoon(days int) bool {
	if w.Data.ExpirationDate == "" {
		return false
	}
	
	expDate, err := time.Parse("2006-01-02", w.Data.ExpirationDate)
	if err != nil {
		return false
	}
	
	daysLeft := int(expDate.Sub(time.Now()).Hours() / 24)
	return daysLeft >= 0 && daysLeft <= days
}

func (w *WhoisLookup) ToJSON() (string, error) {
	jsonData, err := json.MarshalIndent(w.Data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (w *WhoisLookup) PrintResults(verbose bool) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("WHOIS Lookup Results for: %s\n", w.Domain)
	fmt.Printf("%s\n\n", strings.Repeat("=", 60))
	
	if verbose {
		// Detailed output
		jsonData, _ := json.MarshalIndent(w.Data, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		// Summary output
		fmt.Printf("Registrar:        %s\n", w.Data.Registrar)
		fmt.Printf("Created:          %s\n", w.Data.CreationDate)
		fmt.Printf("Expires:          %s\n", w.Data.ExpirationDate)
		fmt.Printf("Name Servers:     %s\n", strings.Join(w.Data.NameServers, ", "))
		fmt.Printf("Registrant Org:   %s\n", w.Data.Org)
		
		if w.IsExpiringSoon(30) {
			fmt.Printf("\n⚠️  WARNING: Domain expires within 30 days!\n")
		}
	}
	
	fmt.Printf("\n%s\n\n", strings.Repeat("=", 60))
}

func main() {
	domain := flag.String("d", "", "Domain name to lookup")
	verbose := flag.Bool("v", false, "Show detailed information")
	jsonOutput := flag.Bool("j", false, "Output as JSON")
	summary := flag.Bool("s", false, "Show summary only")
	timeout := flag.Int("t", 10, "Timeout in seconds")
	output := flag.String("o", "", "Output file to save results")
	flag.Parse()
	
	if *domain == "" {
		fmt.Println("Error: Domain is required")
		flag.Usage()
		os.Exit(1)
	}
	
	// Perform lookup
	lookup := NewWhoisLookup(*domain, *timeout)
	if err := lookup.Lookup(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	
	var outputData string
	
	// Output format
	if *jsonOutput {
		jsonStr, _ := lookup.ToJSON()
		outputData = jsonStr
		fmt.Println(jsonStr)
	} else if *summary {
		summaryData, _ := json.MarshalIndent(lookup.GetSummary(), "", "  ")
		outputData = string(summaryData)
		fmt.Println(outputData)
	} else {
		lookup.PrintResults(*verbose)
	}
	
	// Save to file
	if *output != "" {
		if outputData == "" {
			outputData, _ = lookup.ToJSON()
		}
		err := os.WriteFile(*output, []byte(outputData), 0644)
		if err != nil {
			fmt.Printf("Error saving results: %v\n", err)
		} else {
			fmt.Printf("\n[+] Results saved to %s\n", *output)
		}
	}
}
