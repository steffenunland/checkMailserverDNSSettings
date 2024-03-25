package main

import (
	"checkMailserver/pkg/dnscheck"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
	"golang.org/x/term"
)

const helpDocs = `mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.
Commands:`

type mailserverRecordSet struct {
	MX          []*net.MX
	ipAddress   []net.IP
	spfRecords  []string
	reverseAddr []string
	dkimRecord  []string
}

var mailserverDomain string

func init() {
	flag.StringVar(&mailserverDomain, "domain", "", "The domain whose records you want to check.")
}

// Color grid
func colorGrid(xSteps, ySteps int) [][]string {
	x0y0, _ := colorful.Hex("#F25D94")
	x1y0, _ := colorful.Hex("#EDFF82")
	x0y1, _ := colorful.Hex("#643AFF")
	x1y1, _ := colorful.Hex("#14F9D5")

	x0 := make([]colorful.Color, ySteps)
	for i := range x0 {
		x0[i] = x0y0.BlendLuv(x0y1, float64(i)/float64(ySteps))
	}

	x1 := make([]colorful.Color, ySteps)
	for i := range x1 {
		x1[i] = x1y0.BlendLuv(x1y1, float64(i)/float64(ySteps))
	}

	grid := make([][]string, ySteps)
	for x := 0; x < ySteps; x++ {
		y0 := x0[x]
		grid[x] = make([]string, xSteps)
		for y := 0; y < xSteps; y++ {
			grid[x][y] = y0.BlendLuv(x1[x], float64(y)/float64(xSteps)).Hex()
		}
	}

	return grid
}

const (
	// In real life situations we'd adjust the document to fit the width we've
	// detected. In the case of this example we're hardcoding the width, and
	// later using the detected width only to truncate in order to avoid jaggy
	// wrapping.
	width = 96

	columnWidth = 30
)

// Style definitions.
var (

	// General.

	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}

	// Status Bar.

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

	statusUNKNOWNStyle = lipgloss.NewStyle().
				Inherit(statusBarStyle).
				Foreground(lipgloss.Color("#FFFDF5")).
				Background(lipgloss.Color("#ff0000")).
				Padding(0, 1).
				MarginRight(1)

	statusText = lipgloss.NewStyle().Inherit(statusBarStyle)

	// Page.

	docStyle = lipgloss.NewStyle().Padding(1, 2, 1, 2)
)

func generateContent(status int, context string, content string) {
	{
		w := lipgloss.Width
		statusKey := statusUNKNOWNStyle.Render("UNKNOWN")

		if status == 1 {
			statusKey = statusOKStyle.Render("OKAY")
		} else {
			statusKey = statusCriticalStyle.Render("CRITICAL")

		}

		statusVal := statusText.Copy().
			Width(width - w(statusKey)).
			Render(context + content)

		bar := lipgloss.JoinHorizontal(lipgloss.Top,
			statusKey,
			statusVal,
		)

		doc.WriteString(statusBarStyle.Width(width).Render(bar) + "\n")
	}

}

// Global Var
var doc = strings.Builder{}

func main() {

	flag.Parse()

	physicalWidth, _, _ := term.GetSize(int(os.Stdout.Fd()))

	if mailserverDomain == "" {
		print(helpDocs)
		flag.PrintDefaults()
		os.Exit(1)
	}

	ipAddress := dnscheck.LookupIP(mailserverDomain)

	for i := range ipAddress {
		generateContent(1, "IP-ADDRESS: ", ipAddress[i].String())

	}

	mxRecords := dnscheck.LookupMX(mailserverDomain)

	for i := range mxRecords {
		generateContent(1, "MX Records: ", mxRecords[i].Host)
	}

	reverseAddr := dnscheck.LookupReverseAddr(mailserverDomain, ipAddress[0].String())

	for i := range reverseAddr {
		generateContent(1, "ReverseAddr: ", reverseAddr[i])
	}

	spfRecord := dnscheck.LookupSPF(mailserverDomain)
	if spfRecord != "" {
		generateContent(1, "SPF Record: ", spfRecord)
	} else {
		generateContent(0, "SPF Record: ", "can't find SPF record")
	}

	dkimRecord := dnscheck.LookupDKIM(mailserverDomain)
	if dkimRecord == nil {
		generateContent(2, "DKIM Record: ", "Can't find a record")
	}
	for i := range dkimRecord {
		generateContent(1, "DKIM Record: ", dkimRecord[i])
	}

	if physicalWidth > 0 {
		docStyle = docStyle.MaxWidth(physicalWidth)
	}
	// Okay, let's print it
	fmt.Println(docStyle.Render(doc.String()))
}
