package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

type ipifyResponse struct {
	IPv6 *string `json:"ip"`
}

func setupLogger(filePath string, debugMode bool) (*os.File, error) {
	// ? https://stackoverflow.com/a/13513490/19020549
	f1, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("error opening log file: %w", err)
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if debugMode {
		opts.Level = slog.LevelDebug
	}

	mw := io.MultiWriter(os.Stdout, f1)
	logger := slog.New(slog.NewTextHandler(mw, opts))
	slog.SetDefault(logger)

	return f1, nil
}

func getIPv6(httpClient http.Client, url string) (string, error) {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return "", fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("response status is not OK: %d", resp.StatusCode)
	}

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	slog.Debug("Unmarshalling response body")
	ipifyResponse1 := ipifyResponse{}
	jsonErr := json.Unmarshal(body, &ipifyResponse1)
	if jsonErr != nil {
		return "", fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if ipifyResponse1.IPv6 == nil {
		return "", fmt.Errorf("response body does not contain IP field")
	}

	// ! Extremely basic check for IPv6
	// ? Sometimes ipify returns IPv4
	if !strings.Contains(*ipifyResponse1.IPv6, ":") {
		return "", fmt.Errorf("IP is not IPv6")
	}

	return *ipifyResponse1.IPv6, nil
}

func main() {
	logPath := flag.String("logPath", "./vaf.log", "Path to log file")
	debugMode := flag.Bool("debug", true, "Enable debug mode")
	ipv6URL := flag.String("ipv6URL", "https://api64.ipify.org?format=json", "URL to fetch IPv6 from")
	flag.Parse()

	slog.Info("Starting virgin-auto-firewall", slog.String("logPath", *logPath), slog.String("ipv6URL", *ipv6URL))
	slog.Info("Setting up logger", slog.String("logPath", *logPath))

	f1, err := setupLogger(*logPath, *debugMode)
	if err != nil {
		slog.Error(err.Error())
		slog.Error("virgin-auto-firewall failed to start, exiting")
		os.Exit(1)
	}

	defer f1.Close()

	slog.Info("virgin-auto-firewall started successfully", slog.String("logPath", *logPath), slog.String("ipv6URL", *ipv6URL))

	httpClient := http.Client{
		Timeout: time.Second * 2,
	}

	slog.Info("Fetching IPv6 address", slog.String("ipv6URL", *ipv6URL))
	ipv6, err := getIPv6(httpClient, *ipv6URL)
	if err != nil {
		slog.Error(err.Error())
		slog.Error("virgin-auto-firewall failed to get IPv6, exiting")
		os.Exit(1)
	}

	slog.Info("Fetched IPv6 successfully", slog.String("IPv6", ipv6))
}
