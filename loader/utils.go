package loader

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/swoiow/dns_utils/parsers"
)

const (
	MinDomainLen = 3
	MaxDomainLen = 63
)

var httpFlag = regexp.MustCompile(`(?i)http://`)
var httpsFlag = regexp.MustCompile(`(?i)https://`)
var cacheFlag = regexp.MustCompile(`(?i)cache\+`)

// select parsers
var hostsFlag = regexp.MustCompile(`(?i)hosts\+`)
var surgeFlag = regexp.MustCompile(`(?i)surge\+`)
var dnsmasqFlag = regexp.MustCompile(`(?i)dnsmasq\+`)
var domainFlag = regexp.MustCompile(`(?i)domain\+`)

// control strict mode of parser
var strictFlag = regexp.MustCompile(`(?i)strict\+`)
var localFlag = regexp.MustCompile(`(?i)local\+`)

type Methods struct {
	RawInput string
	OutInput string

	IsCache bool
	IsRules bool

	IsHttp   bool
	IsHttps  bool
	IsRemote bool

	// strictMode 表明在校验域名时，域名必须为带`.`号
	StrictMode bool

	UseHostsParser   bool
	UseSurgeParser   bool
	UseDnsmasqParser bool
	UseDomainParser  bool

	HttpClient *http.Client
}

func DetectMethods(rawIn string) *Methods {
	m := &Methods{}
	m.RawInput = rawIn
	m.OutInput = rawIn

	if cacheFlag.MatchString(rawIn) || strings.HasSuffix(strings.ToLower(rawIn), ".dat") {
		m.IsCache = true
		m.OutInput = cacheFlag.ReplaceAllLiteralString(m.OutInput, "")
	} else {
		m.IsRules = true
	}

	if hostsFlag.MatchString(rawIn) {
		m.UseHostsParser = true
		m.OutInput = hostsFlag.ReplaceAllLiteralString(m.OutInput, "")
	} else if surgeFlag.MatchString(rawIn) {
		m.UseSurgeParser = true
		m.OutInput = surgeFlag.ReplaceAllLiteralString(m.OutInput, "")
	} else if dnsmasqFlag.MatchString(rawIn) {
		m.UseDnsmasqParser = true
		m.OutInput = dnsmasqFlag.ReplaceAllLiteralString(m.OutInput, "")
	} else if domainFlag.MatchString(rawIn) {
		m.UseDomainParser = true
		m.OutInput = domainFlag.ReplaceAllLiteralString(m.OutInput, "")
	}

	if httpFlag.MatchString(rawIn) {
		m.IsHttp = true
		m.IsRemote = true
	} else if httpsFlag.MatchString(rawIn) {
		m.IsHttps = true
		m.IsRemote = true
	} else {
		m.IsRemote = false
	}

	if strictFlag.MatchString(rawIn) {
		m.StrictMode = true
		m.OutInput = strictFlag.ReplaceAllLiteralString(m.OutInput, "")
	} else if localFlag.MatchString(rawIn) {
		m.StrictMode = false
		m.OutInput = localFlag.ReplaceAllLiteralString(m.OutInput, "")
	}

	tp := http.Transport{
		IdleConnTimeout: 60 * time.Second,
	}
	m.HttpClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &tp,
	}
	return m
}

func (m Methods) SetupResolver(resolver string) {
	// https://koraygocmen.medium.com/custom-dns-resolver-for-the-default-http-client-in-go-a1420db38a5d
	var (
		dnsResolverIP        = resolver
		dnsResolverProto     = "udp"
		dnsResolverTimeoutMs = 4500
	)

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	m.HttpClient.Transport.(*http.Transport).DialContext = dialCtx
}

func (m Methods) ResetResolver() {
	m.HttpClient.Transport.(*http.Transport).DialContext = nil
}

func (m Methods) LoadRules(strictMode bool) ([]string, error) {
	/* The input samples:
	hosts+
	surge+
	dnsmasq+
	domain+

	https://example.com/reject-list.txt
	*/

	var (
		rawLines []string
		resLines []string
		err      error
	)

	if m.IsRemote {
		rawLines, err = m.urlToLines(m.OutInput)
		if err != nil {
			return nil, err
		}
	} else {
		rawLines, err = FileToLines(m.OutInput)
		if err != nil {
			return nil, err
		}
	}

	if m.IsRemote || (strictMode || m.StrictMode) {
		resLines = parsers.FuzzyParserSupportWildcard(rawLines, 1)
	} else {
		resLines = parsers.LooseParser(rawLines, parsers.DomainParser, 1)
	}

	return resLines, nil
}

func (m Methods) LoadCache(filter *bloom.BloomFilter) error {
	/* The input samples:
	cache+/AAA/bbb/ccc.dat
	cache+domains.dat
	cache+https://domains.dat
	*/

	if m.IsRemote {
		resp, err := m.HttpClient.Get(m.OutInput)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		_, err = filter.ReadFrom(resp.Body)
		if err != nil {
			return err
		}
	} else {
		rf, err := os.Open(m.OutInput)
		if err != nil {
			return err
		}
		defer rf.Close()

		_, err = filter.ReadFrom(rf)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m Methods) urlToLines(url string) ([]string, error) {
	/* Load rules from remote
	 */

	resp, err := m.HttpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return linesFromReader(resp.Body)
}

func FileToLines(path string) ([]string, error) {
	/* Load rules from local
	 */

	rf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rf.Close()
	return linesFromReader(rf)
}

func UrlToLines(url string) ([]string, error) {
	/* Load rules from remote
	 */
	transport := http.Transport{
		IdleConnTimeout: 60 * time.Second,
	}
	client := http.Client{
		Timeout:   45 * time.Second,
		Transport: &transport,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return linesFromReader(resp.Body)
}

func linesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
