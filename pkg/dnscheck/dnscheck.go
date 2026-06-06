package dnscheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func LookupIP(r *net.Resolver, domain string) []net.IP {
	ipAddress, err := r.LookupIPAddr(context.Background(), domain)
	if err != nil {
		return nil
	}
	result := make([]net.IP, len(ipAddress))
	for i, addr := range ipAddress {
		result[i] = addr.IP
	}
	return result
}

func LookupMX(r *net.Resolver, domain string) []*net.MX {
	mxRecords, err := r.LookupMX(context.Background(), domain)
	if err != nil {
		return nil
	}
	return mxRecords
}

func LookupReverseAddr(r *net.Resolver, ip string) []string {
	reverseAddr, err := r.LookupAddr(context.Background(), ip)
	if err != nil {
		return nil
	}
	return reverseAddr
}

// lookupTXTWithPrefix returns all TXT records at the given name whose content
// starts (case-insensitively, ignoring leading whitespace) with prefix.
func lookupTXTWithPrefix(r *net.Resolver, name string, prefix string) []string {
	txtRecords, err := r.LookupTXT(context.Background(), name)
	if err != nil {
		return nil
	}
	var results []string
	for _, rr := range txtRecords {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rr)), strings.ToLower(prefix)) {
			results = append(results, rr)
		}
	}
	return results
}

func LookupSPF(r *net.Resolver, domain string) []string {
	txtRecords, err := r.LookupTXT(context.Background(), domain)
	if err != nil {
		return nil
	}

	spfPattern := regexp.MustCompile(`(?i)\s*v=spf1\b.*`)
	var results []string
	for _, rr := range txtRecords {
		if spfPattern.MatchString(rr) {
			results = append(results, rr)
		}
	}
	return results
}

// SPFQualifier returns the qualifier of the terminal "all" mechanism in an SPF
// record: "-" (fail/strict), "~" (softfail), "?" (neutral), "+" (pass/insecure)
// or "" if no all mechanism is present.
func SPFQualifier(record string) string {
	m := regexp.MustCompile(`(?i)([-~?+]?)all\b`).FindStringSubmatch(record)
	if m == nil {
		return ""
	}
	if m[1] == "" {
		return "+" // a bare "all" defaults to pass
	}
	return m[1]
}

func LookupDKIM(r *net.Resolver, domain string, selector string) ([]string, error) {
	dkimRecord, err := r.LookupTXT(context.Background(), fmt.Sprintf("%s._domainkey.%s", selector, domain))
	if err != nil {
		return nil, err
	}
	return dkimRecord, nil
}

func LookupDMARC(r *net.Resolver, domain string) []string {
	return lookupTXTWithPrefix(r, "_dmarc."+domain, "v=DMARC1")
}

// DMARCPolicy returns the value of the p= tag (none/quarantine/reject) of a
// DMARC record, or "" if absent.
func DMARCPolicy(record string) string {
	m := regexp.MustCompile(`(?i)\bp\s*=\s*(none|quarantine|reject)\b`).FindStringSubmatch(record)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

func LookupMTASTS(r *net.Resolver, domain string) []string {
	return lookupTXTWithPrefix(r, "_mta-sts."+domain, "v=STSv1")
}

// FetchMTASTSPolicy retrieves the MTA-STS policy file published over HTTPS at
// mta-sts.<domain>/.well-known/mta-sts.txt. Returns the raw policy body.
func FetchMTASTSPolicy(domain string) (string, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// MTASTSMode returns the value of the "mode" line (enforce/testing/none) of an
// MTA-STS policy body, or "" if absent.
func MTASTSMode(policy string) string {
	m := regexp.MustCompile(`(?im)^\s*mode\s*:\s*(enforce|testing|none)\b`).FindStringSubmatch(policy)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

func LookupTLSRPT(r *net.Resolver, domain string) []string {
	return lookupTXTWithPrefix(r, "_smtp._tls."+domain, "v=TLSRPTv1")
}

func LookupBIMI(r *net.Resolver, domain string, selector string) []string {
	return lookupTXTWithPrefix(r, selector+"._bimi."+domain, "v=BIMI1")
}
