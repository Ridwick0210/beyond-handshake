// A browserless Go net/http adapter for the local catalog task.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const maxResponseBytes = 2*1024*1024 + 1

var (
	termPattern    = regexp.MustCompile(`(?s)<b>([^<]+)</b>`)
	itemPattern    = regexp.MustCompile(`name=item_id value="([^"]+)"`)
	noncePattern   = regexp.MustCompile(`name=nonce value="([^"]+)"`)
	sessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
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

type response struct {
	Status   int
	Body     []byte
	Protocol string
}

func main() {
	var origin, caFile, session string
	var timeout time.Duration
	var version bool
	flag.StringVar(&origin, "origin", "", "local HTTPS task origin")
	flag.StringVar(&caFile, "ca", "", "trusted local CA PEM")
	flag.StringVar(&session, "session", "", "registered task session ID")
	flag.DurationVar(&timeout, "timeout", 45*time.Second, "task deadline")
	flag.BoolVar(&version, "version", false, "print Go runtime version")
	flag.Parse()
	if version {
		fmt.Println(runtime.Version())
		return
	}
	out := result{Steps: []step{}}
	if err := execute(&out, origin, caFile, session, timeout); err != nil {
		out.Error = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if out.Error != "" {
		os.Exit(1)
	}
}

func execute(out *result, origin, caFile, session string, timeout time.Duration) error {
	if !sessionPattern.MatchString(session) || timeout <= 0 {
		return errors.New("invalid session or deadline")
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
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS12,
	}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	baseURL := strings.TrimSuffix(origin, "/")
	path := "/s/" + session

	start, err := request(ctx, client, http.MethodGet, baseURL+path+"/start", "", "")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	out.Steps = append(out.Steps, step{"start", start.Status})
	match := termPattern.FindSubmatch(start.Body)
	if len(match) != 2 {
		return errors.New("start page has no task search term")
	}
	term := html.UnescapeString(string(match[1]))
	searchURL := baseURL + path + "/api/search?q=" + url.QueryEscape(term)
	search, err := request(ctx, client, http.MethodGet, searchURL, "", "")
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
	detail, err := request(ctx, client, http.MethodGet, baseURL+itemURL.Path, "", "")
	if err != nil {
		return fmt.Errorf("detail: %w", err)
	}
	out.Steps = append(out.Steps, step{"detail", detail.Status})
	item := itemPattern.FindSubmatch(detail.Body)
	nonce := noncePattern.FindSubmatch(detail.Body)
	if len(item) != 2 || len(nonce) != 2 {
		return errors.New("detail page has no save fields")
	}
	formValues := url.Values{"item_id": {string(item[1])}, "nonce": {string(nonce[1])}}
	if answer := termPattern.FindSubmatch(detail.Body); len(answer) == 2 {
		formValues.Set("answer", html.UnescapeString(string(answer[1])))
	}
	form := formValues.Encode()
	save, err := request(ctx, client, http.MethodPost, baseURL+path+"/api/save", form,
		"application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("save: %w", err)
	}
	out.Steps = append(out.Steps, step{"save_api", save.Status})
	complete, err := request(ctx, client, http.MethodGet, baseURL+path+"/complete", "", "")
	if err != nil {
		return fmt.Errorf("confirmation: %w", err)
	}
	out.Steps = append(out.Steps, step{"confirmation", complete.Status})
	out.Protocol = normalizedProtocol(complete.Protocol)
	return nil
}

func normalizedProtocol(protocol string) string {
	switch protocol {
	case "HTTP/2.0":
		return "h2"
	case "HTTP/1.1":
		return "http/1.1"
	default:
		return strings.ToLower(protocol)
	}
}

func request(ctx context.Context, client *http.Client, method, target, body, contentType string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return response{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return response{}, err
	}
	if len(data) >= maxResponseBytes {
		return response{}, errors.New("response exceeded the client body limit")
	}
	if res.StatusCode != http.StatusOK {
		return response{}, fmt.Errorf("task endpoint returned HTTP %d", res.StatusCode)
	}
	return response{res.StatusCode, data, res.Proto}, nil
}
