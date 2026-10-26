// Local-only stage-1 task runner using the pinned Go tls-client Chrome profile.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	adapterVersion  = "tls-client-v1.16.0"
	maxResponseSize = 2*1024*1024 + 1
)

var (
	sessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	termPattern    = regexp.MustCompile(`(?s)<b>([^<]+)</b>`)
	itemPattern    = regexp.MustCompile(`name=item_id value="([^"]+)"`)
	noncePattern   = regexp.MustCompile(`name=nonce value="([^"]+)"`)
)

type step struct {
	Route  string `json:"route"`
	Status int    `json:"status"`
}

type result struct {
	Protocol string `json:"protocol,omitempty"`
	Steps    []step `json:"steps"`
	Error    string `json:"error,omitempty"`
}

func main() {
	var origin, caFile, session, profile string
	var timeout time.Duration
	var showVersion bool
	flag.StringVar(&origin, "origin", "", "local HTTPS task origin")
	flag.StringVar(&caFile, "ca", "", "trusted local CA PEM")
	flag.StringVar(&session, "session", "", "registered task session ID")
	flag.StringVar(&profile, "profile", "", "pinned browser profile")
	flag.DurationVar(&timeout, "timeout", 45*time.Second, "task deadline")
	flag.BoolVar(&showVersion, "version", false, "print adapter and Go versions")
	flag.Parse()
	if showVersion {
		fmt.Printf("%s %s\n", adapterVersion, runtime.Version())
		return
	}
	out := result{Steps: []step{}}
	if err := execute(&out, origin, caFile, session, profile, timeout); err != nil {
		out.Error = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if out.Error != "" {
		os.Exit(1)
	}
}

func execute(out *result, origin, caFile, session, profile string, timeout time.Duration) error {
	if !sessionPattern.MatchString(session) || timeout <= 0 {
		return errors.New("invalid session or deadline")
	}
	if profile != "chrome_150" {
		return errors.New("stage 1 requires the pinned chrome_150 profile")
	}
	base, err := url.Parse(origin)
	if err != nil || base.Scheme != "https" || base.User != nil || base.RawQuery != "" ||
		base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return errors.New("origin must be a local HTTPS root")
	}
	if host := base.Hostname(); host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return errors.New("origin host must be loopback")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read trusted CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("trusted CA PEM contains no certificates")
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(int(timeout.Seconds())),
		tlsclient.WithClientProfile(profiles.Chrome_150),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithDisableHttp3(),
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{RootCAs: roots}),
	)
	if err != nil {
		return fmt.Errorf("create verified profile client: %w", err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	baseURL := strings.TrimSuffix(origin, "/")
	path := "/s/" + session

	start, err := request(ctx, client, http.MethodGet, baseURL+path+"/start", "", "html")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	out.Steps = append(out.Steps, step{"start", start.Status})
	match := termPattern.FindSubmatch(start.Body)
	if len(match) != 2 {
		return errors.New("start page has no task search term")
	}
	searchURL := baseURL + path + "/api/search?q=" + url.QueryEscape(string(match[1]))
	search, err := request(ctx, client, http.MethodGet, searchURL, "", "json")
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	out.Steps = append(out.Steps, step{"search_api", search.Status})
	var catalog struct {
		Items []struct {
			URL string `json:"url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(search.Body, &catalog); err != nil || len(catalog.Items) != 1 {
		return errors.New("search did not return exactly one item")
	}
	itemURL, err := url.Parse(catalog.Items[0].URL)
	if err != nil || itemURL.IsAbs() || itemURL.Host != "" || itemURL.RawQuery != "" ||
		itemURL.Fragment != "" || !strings.HasPrefix(itemURL.Path, path+"/item/") {
		return errors.New("item URL escaped the task session")
	}
	detail, err := request(ctx, client, http.MethodGet, baseURL+itemURL.Path, "", "html")
	if err != nil {
		return fmt.Errorf("detail: %w", err)
	}
	out.Steps = append(out.Steps, step{"detail", detail.Status})
	item := itemPattern.FindSubmatch(detail.Body)
	nonce := noncePattern.FindSubmatch(detail.Body)
	if len(item) != 2 || len(nonce) != 2 {
		return errors.New("detail page has no save fields")
	}
	form := url.Values{"item_id": {string(item[1])}, "nonce": {string(nonce[1])}}.Encode()
	save, err := request(ctx, client, http.MethodPost, baseURL+path+"/api/save", form, "form")
	if err != nil {
		return fmt.Errorf("save: %w", err)
	}
	out.Steps = append(out.Steps, step{"save_api", save.Status})
	complete, err := request(ctx, client, http.MethodGet, baseURL+path+"/complete", "", "html")
	if err != nil {
		return fmt.Errorf("confirmation: %w", err)
	}
	out.Steps = append(out.Steps, step{"confirmation", complete.Status})
	out.Protocol = normalizeProtocol(complete.Protocol)
	return nil
}

func normalizeProtocol(protocol string) string {
	switch protocol {
	case "HTTP/2.0", "HTTP/2":
		return "h2"
	case "HTTP/1.1":
		return "http/1.1"
	default:
		return strings.ToLower(protocol)
	}
}

type response struct {
	Status   int
	Body     []byte
	Protocol string
}

func request(ctx context.Context, client tlsclient.HttpClient, method, target, body, accept string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return response{}, err
	}
	acceptValue := "*/*"
	if accept == "html" {
		acceptValue = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	} else if accept == "json" {
		acceptValue = "application/json, text/plain, */*"
	} else if accept == "form" {
		acceptValue = "*/*"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header = http.Header{
		"User-Agent":        {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
		"Accept":            {acceptValue},
		"Accept-Language":   {"en-US,en;q=0.9"},
		http.HeaderOrderKey: {"user-agent", "accept", "accept-language", "content-type"},
	}
	if accept == "form" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize))
	if err != nil {
		return response{}, err
	}
	if len(data) >= maxResponseSize {
		return response{}, errors.New("response exceeded the client body limit")
	}
	if res.StatusCode != http.StatusOK {
		return response{}, fmt.Errorf("task endpoint returned HTTP %d", res.StatusCode)
	}
	return response{res.StatusCode, data, res.Proto}, nil
}
