package dnscheck

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

func LookupIP(domain string) []net.IP {
	ipAddress, err := net.LookupIP(domain)
	if err != nil {
		return nil
	}
	return ipAddress
}

func LookupMX(domain string) []*net.MX {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil
	}
	return mxRecords
}

func LookupReverseAddr(domain string, ip string) []string {
	reverseAddr, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	return reverseAddr
}

// FRAGEN:
// KANN EINE SEITE MEHRERE SPF Records haben?

func LookupSPF(domain string) string {
	spfRecord, err := net.LookupTXT(domain)
	returnValue := ""

	if err != nil {
		return returnValue
	}

	// Obviously, this is a very, very simple pattern.
	// It lacks any true validation whether the TXT record
	// is in fact a valid SPF. Expanding the regex should
	// not be too hard and I leave it up to you.
	spfPattern := regexp.MustCompile(`\s*v=spf1.*`)

	// Now we have all TXT records for the domain we iterate through them...
	for _, rr := range spfRecord {
		// ... and if one of them matches the pattern of an SPF record...
		if spfPattern.MatchString(rr) {
			returnValue = rr
		}
	}

	return returnValue
}

func LookupDKIM(domain string) []string {
	dkimRecord, err := net.LookupTXT(fmt.Sprintf("dk._domainkey.%s", domain))
	if err != nil {
		return nil
	}

	//fmt.Println(dkimRecord[0])
	r := strings.NewReader(dkimRecord[0])
	fmt.Println(dkim.Verify(r))
	return dkimRecord
}
