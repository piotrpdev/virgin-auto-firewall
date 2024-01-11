package main

import (
	"bytes"
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

type loginResponse struct {
	Created struct {
		BearerToken *string `json:"token"`
		UserLevel   *string `json:"userLevel"`
		UserID      *int    `json:"userId"`
	} `json:"created"`
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

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("response status is not OK: %d", resp.StatusCode)
	}

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

func login(httpClient http.Client, url string, routerPassword string) (string, string, error) {
	var jsonData = []byte(fmt.Sprintf("{\"password\": \"%s\"}", routerPassword))

	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return "", "", fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("response status is not correct (expected 201): %d", resp.StatusCode)
	}

	slog.Debug("Unmarshalling response body")
	loginResponse1 := loginResponse{}
	jsonErr := json.Unmarshal(body, &loginResponse1)
	if jsonErr != nil {
		return "", "", fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if loginResponse1.Created.BearerToken == nil {
		return "", "", fmt.Errorf("response body does not contain token field")
	}

	if loginResponse1.Created.UserID == nil {
		return "", "", fmt.Errorf("response body does not contain userId field")
	}

	return fmt.Sprintf("%d", *loginResponse1.Created.UserID), *loginResponse1.Created.BearerToken, nil
}

func logout(httpClient http.Client, url string, bearerToken string) (int, error) {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return -1, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return -1, fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return -1, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusNoContent {
		return -1, fmt.Errorf("response status is not correct (expected 204): %d", resp.StatusCode)
	}

	return resp.StatusCode, nil
}

func main() {
	logPath := flag.String("logPath", "./vaf.log", "Path to log file")
	debugMode := flag.Bool("debug", true, "Enable debug mode")
	ipv6URL := flag.String("ipv6URL", "https://api64.ipify.org?format=json", "URL to fetch IPv6 from")
	routerPassword := flag.String("routerPassword", "", "Router password")
	loginURL := flag.String("loginURL", "http://192.168.0.1/rest/v1/user/login", "URL to login to router")
	logoutURL := flag.String("logoutURL", "http://192.168.0.1/rest/v1/user/%s/token/%s", "URL to logout of router")
	flag.Parse()

	slog.Info("Starting virgin-auto-firewall", slog.String("logPath", *logPath), slog.Bool("debugMode", *debugMode), slog.String("ipv6URL", *ipv6URL), slog.String("routerPassword", *routerPassword), slog.String("loginURL", *loginURL), slog.String("logoutURL", *logoutURL))
	slog.Info("Setting up logger", slog.String("logPath", *logPath))

	f1, err := setupLogger(*logPath, *debugMode)
	if err != nil {
		slog.Error(err.Error())
		slog.Error("virgin-auto-firewall failed to start, exiting")
		os.Exit(1)
	}

	defer f1.Close()

	slog.Info("virgin-auto-firewall started successfully", slog.String("logPath", *logPath), slog.Bool("debugMode", *debugMode), slog.String("ipv6URL", *ipv6URL), slog.String("routerPassword", *routerPassword), slog.String("loginURL", *loginURL), slog.String("logoutURL", *logoutURL))

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

	slog.Info("Attempting to login", slog.String("loginURL", *loginURL), slog.String("routerPassword", *routerPassword))
	userId, bearerToken, loginErr := login(httpClient, *loginURL, *routerPassword)
	if loginErr != nil {
		slog.Error(loginErr.Error())
		slog.Error("virgin-auto-firewall failed to login, exiting")
		os.Exit(1)
	}

	slog.Info("Logged in successfully", slog.String("bearerToken", bearerToken))

	slog.Info("Attempting to logout", slog.String("logoutURL", fmt.Sprintf(*logoutURL, userId, bearerToken)), slog.String("bearerToken", bearerToken))
	logoutStatusCode, logoutErr := logout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
	if logoutErr != nil {
		slog.Error(logoutErr.Error())
		slog.Error("virgin-auto-firewall failed to logout, exiting")
		os.Exit(1)
	}

	slog.Info("Logged out successfully", slog.Int("logoutStatusCode", logoutStatusCode))
}
