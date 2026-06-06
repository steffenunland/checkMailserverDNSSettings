package main

import (
	"checkMailserver/pkg/dnscheck"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var resolverAddr string

func newResolver() *net.Resolver {
	if resolverAddr == "" {
		return net.DefaultResolver
	}
	addr := resolverAddr
	if !strings.Contains(addr, ":") {
		addr = addr + ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

const helpDocs = `mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.
Commands:`

var mailserverDomain string
var dkimSelector string
var bimiSelector string
var checkMTASTSPolicy bool

func init() {
	flag.StringVar(&mailserverDomain, "domain", "", "The domain whose records you want to check.")
	flag.StringVar(&dkimSelector, "dkim-selector", "default", "The DKIM selector to look up (default: \"default\").")
	flag.StringVar(&bimiSelector, "bimi-selector", "default", "The BIMI selector to look up (default: \"default\").")
	flag.StringVar(&resolverAddr, "resolver", "", "External DNS resolver to use, e.g. 8.8.8.8 or 1.1.1.1:53 (default: system resolver).")
	flag.BoolVar(&checkMTASTSPolicy, "mta-sts-policy", false, "Also fetch the MTA-STS policy file over HTTPS and check its mode.")
}

const (
	width       = 96
	columnWidth = 30
)

var (
	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}

	statusNugget = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#343433", Dark: "#C1C6B2"}).
			Background(lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#353533"})

	statusOKStyle = lipgloss.NewStyle().
			Inherit(statusBarStyle).
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#006400")).
			Padding(0, 1).
			MarginRight(1)

	statusCriticalStyle = lipgloss.NewStyle().
				Inherit(statusBarStyle).
				Foreground(lipgloss.Color("#FFFDF5")).
				Background(lipgloss.Color("#ff0000")).
				Padding(0, 1).
				MarginRight(1)

	statusWarnStyle = lipgloss.NewStyle().
			Inherit(statusBarStyle).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#FFA500")).
			Padding(0, 1).
			MarginRight(1)

	statusText = lipgloss.NewStyle().Inherit(statusBarStyle)

	docStyle = lipgloss.NewStyle().Padding(1, 2, 1, 2)
)

var doc = strings.Builder{}

type status int

const (
	statusOK       status = iota
	statusCritical status = iota
	statusWarn     status = iota
)

func generateContent(s status, context string, content string) {
	w := lipgloss.Width
	var statusKey string
	switch s {
	case statusOK:
		statusKey = statusOKStyle.Render("OKAY")
	case statusWarn:
		statusKey = statusWarnStyle.Render("WARN")
	default:
		statusKey = statusCriticalStyle.Render("CRITICAL")
	}

	statusVal := statusText.Copy().
		Width(width - w(statusKey)).
		Render(context + content)

	bar := lipgloss.JoinHorizontal(lipgloss.Top, statusKey, statusVal)
	doc.WriteString(statusBarStyle.Width(width).Render(bar) + "\n")
}

func main() {
	flag.Parse()

	physicalWidth, _, _ := term.GetSize(int(os.Stdout.Fd()))

	if mailserverDomain == "" {
		print(helpDocs)
		flag.PrintDefaults()
		os.Exit(1)
	}

	r := newResolver()

	// A records
	ipAddresses := dnscheck.LookupIP(r, mailserverDomain)
	if len(ipAddresses) == 0 {
		generateContent(statusWarn, "IP-ADDRESS: ", "no A record found for domain")
	}
	for _, ip := range ipAddresses {
		generateContent(statusOK, "IP-ADDRESS: ", ip.String())
	}

	// MX records
	mxRecords := dnscheck.LookupMX(r, mailserverDomain)
	if len(mxRecords) == 0 {
		generateContent(statusCritical, "MX Record: ", "no MX record found for domain")
	}
	for _, mx := range mxRecords {
		generateContent(statusOK, "MX Record: ", mx.Host)
	}

	// Reverse DNS for every resolved IP
	for _, ip := range ipAddresses {
		reverseAddrs := dnscheck.LookupReverseAddr(r, ip.String())
		if len(reverseAddrs) == 0 {
			generateContent(statusWarn, "ReverseAddr: ", fmt.Sprintf("no PTR record for %s", ip.String()))
			continue
		}
		for _, addr := range reverseAddrs {
			generateContent(statusOK, fmt.Sprintf("ReverseAddr (%s): ", ip.String()), addr)
		}
	}

	// SPF records
	spfRecords := dnscheck.LookupSPF(r, mailserverDomain)
	if len(spfRecords) == 0 {
		generateContent(statusCritical, "SPF Record: ", "no SPF record found")
	}
	if len(spfRecords) > 1 {
		generateContent(statusCritical, "SPF Record: ", fmt.Sprintf("%d SPF records found — RFC 7208 allows only one", len(spfRecords)))
	}
	for _, spf := range spfRecords {
		generateContent(statusOK, "SPF Record: ", spf)
		switch dnscheck.SPFQualifier(spf) {
		case "-":
			generateContent(statusOK, "SPF Policy: ", "-all (hard fail, strict)")
		case "~":
			generateContent(statusWarn, "SPF Policy: ", "~all (soft fail — consider -all once verified)")
		case "?":
			generateContent(statusWarn, "SPF Policy: ", "?all (neutral — provides no protection)")
		case "+":
			generateContent(statusCritical, "SPF Policy: ", "+all (passes any sender — insecure)")
		default:
			generateContent(statusWarn, "SPF Policy: ", "no 'all' mechanism found")
		}
	}

	// DKIM record
	dkimRecords, err := dnscheck.LookupDKIM(r, mailserverDomain, dkimSelector)
	if err != nil || len(dkimRecords) == 0 {
		generateContent(statusWarn, "DKIM Record: ", fmt.Sprintf("no record found for selector \"%s\"", dkimSelector))
	}
	for _, dkim := range dkimRecords {
		generateContent(statusOK, "DKIM Record: ", dkim)
	}

	// DMARC record
	dmarcRecords := dnscheck.LookupDMARC(r, mailserverDomain)
	if len(dmarcRecords) == 0 {
		generateContent(statusCritical, "DMARC Record: ", "no DMARC record found")
	}
	for _, dmarc := range dmarcRecords {
		generateContent(statusOK, "DMARC Record: ", dmarc)
		switch dnscheck.DMARCPolicy(dmarc) {
		case "reject":
			generateContent(statusOK, "DMARC Policy: ", "p=reject (enforced, strongest)")
		case "quarantine":
			generateContent(statusOK, "DMARC Policy: ", "p=quarantine (enforced)")
		case "none":
			generateContent(statusWarn, "DMARC Policy: ", "p=none (monitoring only — no enforcement)")
		default:
			generateContent(statusWarn, "DMARC Policy: ", "no valid p= tag found")
		}
	}

	// MTA-STS record
	mtaStsRecords := dnscheck.LookupMTASTS(r, mailserverDomain)
	if len(mtaStsRecords) == 0 {
		generateContent(statusWarn, "MTA-STS Record: ", "no MTA-STS record found")
	}
	for _, sts := range mtaStsRecords {
		generateContent(statusOK, "MTA-STS Record: ", sts)
	}
	if len(mtaStsRecords) > 0 && checkMTASTSPolicy {
		policy, perr := dnscheck.FetchMTASTSPolicy(mailserverDomain)
		if perr != nil {
			generateContent(statusWarn, "MTA-STS Policy: ", fmt.Sprintf("could not fetch policy file: %v", perr))
		} else {
			switch dnscheck.MTASTSMode(policy) {
			case "enforce":
				generateContent(statusOK, "MTA-STS Policy: ", "mode: enforce")
			case "testing":
				generateContent(statusWarn, "MTA-STS Policy: ", "mode: testing (not yet enforcing)")
			case "none":
				generateContent(statusWarn, "MTA-STS Policy: ", "mode: none (disabled)")
			default:
				generateContent(statusCritical, "MTA-STS Policy: ", "policy file has no valid mode")
			}
		}
	}

	// TLS-RPT record
	tlsRptRecords := dnscheck.LookupTLSRPT(r, mailserverDomain)
	if len(tlsRptRecords) == 0 {
		generateContent(statusWarn, "TLS-RPT Record: ", "no SMTP TLS reporting record found")
	}
	for _, tlsRpt := range tlsRptRecords {
		generateContent(statusOK, "TLS-RPT Record: ", tlsRpt)
	}

	// BIMI record
	bimiRecords := dnscheck.LookupBIMI(r, mailserverDomain, bimiSelector)
	if len(bimiRecords) == 0 {
		generateContent(statusWarn, "BIMI Record: ", fmt.Sprintf("no record found for selector \"%s\"", bimiSelector))
	}
	for _, bimi := range bimiRecords {
		generateContent(statusOK, "BIMI Record: ", bimi)
	}

	if physicalWidth > 0 {
		docStyle = docStyle.MaxWidth(physicalWidth)
	}
	fmt.Println(docStyle.Render(doc.String()))
}
