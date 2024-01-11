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

type devicesResponse struct {
	Hosts struct {
		Hosts *[]struct {
			MacAddress string `json:"macAddress"`
			Config     struct {
				Hostname string `json:"hostname"`
				Ipv4     struct {
					Address            string `json:"address"`
					LeaseTimeRemaining int    `json:"leaseTimeRemaining"`
				} `json:"ipv4"`
				Ipv6 struct {
					LinkLocalAddress   string `json:"linkLocalAddress"`
					GlobalAddress      string `json:"globalAddress"`
					LeaseTimeRemaining int    `json:"leaseTimeRemaining"`
				} `json:"ipv6"`
			} `json:"config"`
		} `json:"hosts"`
	} `json:"hosts"`
}

type ipv6InfoResponse struct {
	Info struct {
		LanIPAddress            string  `json:"lanIpAddress"`
		LanNetworkPrefixAddress *string `json:"lanNetworkPrefixAddress"`
		LanNetworkPrefixLength  int     `json:"lanNetworkPrefixLength"`
	} `json:"info"`
}

type filtersResponse struct {
	Ipportfilters struct {
		Ipv6 struct {
			Rules *[]struct {
				Filter struct {
					Protocol                string `json:"protocol"`
					Enable                  bool   `json:"enable"`
					DestinationStartAddress string `json:"destinationStartAddress"`
					Direction               string `json:"direction"`
					AllowTraffic            bool   `json:"allowTraffic"`
				} `json:"filter"`
				ID int `json:"id"`
			} `json:"rules"`
		} `json:"ipv6"`
	} `json:"ipportfilters"`
}

type addFilterResponse struct {
	Created struct {
		ID  *int   `json:"id"`
		URI string `json:"uri"`
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
		return "", fmt.Errorf("response status is not correct (expected 200): %d", resp.StatusCode)
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
	var jsonData = []byte(fmt.Sprintf(`{"password": "%s"}`, routerPassword))

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

func getConnectedDevices(httpClient http.Client, url string, bearerToken string) (devicesResponse, error) {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return devicesResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return devicesResponse{}, fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return devicesResponse{}, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return devicesResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusOK {
		return devicesResponse{}, fmt.Errorf("response status is not correct (expected 200): %d", resp.StatusCode)
	}

	slog.Debug("Unmarshalling response body")
	devicesResponse1 := devicesResponse{}
	jsonErr := json.Unmarshal(body, &devicesResponse1)
	if jsonErr != nil {
		return devicesResponse{}, fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if devicesResponse1.Hosts.Hosts == nil {
		return devicesResponse{}, fmt.Errorf("response body does not contain hosts field")
	}

	return devicesResponse1, nil
}

func getNetworkIPv6Info(httpClient http.Client, url string, bearerToken string) (ipv6InfoResponse, error) {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ipv6InfoResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return ipv6InfoResponse{}, fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return ipv6InfoResponse{}, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ipv6InfoResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusOK {
		return ipv6InfoResponse{}, fmt.Errorf("response status is not correct (expected 200): %d", resp.StatusCode)
	}

	slog.Debug("Unmarshalling response body")
	ipv6InfoResponse1 := ipv6InfoResponse{}
	jsonErr := json.Unmarshal(body, &ipv6InfoResponse1)
	if jsonErr != nil {
		return ipv6InfoResponse{}, fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if ipv6InfoResponse1.Info.LanNetworkPrefixAddress == nil {
		return ipv6InfoResponse{}, fmt.Errorf("response body does not contain LanNetworkPrefixAddress field")
	}

	return ipv6InfoResponse1, nil
}

func getPortFilters(httpClient http.Client, url string, bearerToken string) (filtersResponse, error) {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return filtersResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return filtersResponse{}, fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return filtersResponse{}, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return filtersResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusOK {
		return filtersResponse{}, fmt.Errorf("response status is not correct (expected 200): %d", resp.StatusCode)
	}

	slog.Debug("Unmarshalling response body")
	filtersResponse1 := filtersResponse{}
	jsonErr := json.Unmarshal(body, &filtersResponse1)
	if jsonErr != nil {
		return filtersResponse{}, fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if filtersResponse1.Ipportfilters.Ipv6.Rules == nil {
		return filtersResponse{}, fmt.Errorf("response body does not contain Ipv6.Rules field")
	}

	return filtersResponse1, nil
}

func deletePortFilter(httpClient http.Client, url string, bearerToken string) error {
	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("response status is not correct (expected 204): %d", resp.StatusCode)
	}

	return nil
}

func addPortFilter(httpClient http.Client, url string, ipv6 string, bearerToken string) (addFilterResponse, error) {
	var jsonData = []byte(fmt.Sprintf(`{
		"filter": {
			"enable": true,
			"protocol": "tcp_udp",
			"direction": "in",
			"allowTraffic": true,
			"sourceStartAddress": "::",
			"sourcePrefixLength": 0,
			"destinationStartAddress": "%s",
			"destinationPrefixLength": 128,
			"sourceStartPort": 0,
			"sourceEndPort": 0,
			"destinationStartPort": 0,
			"destinationEndPort": 0
		}
	}`, ipv6))

	slog.Debug("Creating request")
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return addFilterResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	slog.Debug("Sending request")
	resp, err := httpClient.Do(req)
	if err != nil {
		return addFilterResponse{}, fmt.Errorf("error sending request: %w", err)
	}

	if resp.Body == nil {
		return addFilterResponse{}, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	slog.Debug("Reading response body")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return addFilterResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	slog.Debug("Response body", slog.String("url", url), slog.String("body", string(body)))

	if resp.StatusCode != http.StatusCreated {
		return addFilterResponse{}, fmt.Errorf("response status is not correct (expected 201): %d", resp.StatusCode)
	}

	slog.Debug("Unmarshalling response body")
	addFilterResponse1 := addFilterResponse{}
	jsonErr := json.Unmarshal(body, &addFilterResponse1)
	if jsonErr != nil {
		return addFilterResponse{}, fmt.Errorf("error unmarshalling response body: %w", jsonErr)
	}

	if addFilterResponse1.Created.ID == nil {
		return addFilterResponse{}, fmt.Errorf("response body does not contain ID field")
	}

	return addFilterResponse1, nil
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

func quickLogout(httpClient http.Client, logoutURL string, bearerToken string) {
	slog.Info("Attempting to logout", slog.String("logoutURL", logoutURL), slog.String("bearerToken", bearerToken))
	logoutStatusCode, logoutErr := logout(httpClient, logoutURL, bearerToken)
	if logoutErr != nil {
		slog.Error(logoutErr.Error())
		slog.Error("virgin-auto-firewall failed to logout, exiting")
		os.Exit(1)
	} else {
		slog.Info("Logged out successfully", slog.Int("logoutStatusCode", logoutStatusCode))
	}
}

func main() {
	logPath := flag.String("logPath", "./vaf.log", "Path to log file")
	debugMode := flag.Bool("debug", false, "Enable debug mode")
	checkConnected := flag.Bool("checkConnected", false, "Check new IPv6 is present in connected devices before creating a firewall rule")
	ipv6URL := flag.String("ipv6URL", "https://api6.ipify.org?format=json", "URL to fetch IPv6 from")
	routerPassword := flag.String("routerPassword", "", "Router password")
	sleepTime := flag.Int("sleepTime", 10, "Time to sleep between new IPv6 checks")
	previousIPv6Flag := flag.String("previousIPv6", "aaaa:bbbb:cccc:dddd:aaaa:bbbb:cccc:dddd", "Previous IPv6 (testing purposes)")
	loginURL := flag.String("loginURL", "http://192.168.0.1/rest/v1/user/login", "URL to login to router")
	logoutURL := flag.String("logoutURL", "http://192.168.0.1/rest/v1/user/%s/token/%s", "URL to logout of router")
	devicesURL := flag.String("devicesURL", "http://192.168.0.1/rest/v1/network/hosts?connectedOnly=true", "URL to get connected devices from")
	ipv6InfoURL := flag.String("ipv6InfoURL", "http://192.168.0.1/rest/v1/network/ipv6/info", "URL to get IPv6 info from")
	portFiltersURL := flag.String("portFiltersURL", "http://192.168.0.1/rest/v1/network/ipportfilters", "URL to get port filters from")
	deleteIPv6FiltersURL := flag.String("deleteIPv6FiltersURL", "http://192.168.0.1/rest/v1/network/ipv6/ipportfilters/%d", "URL to delete IPv6 filters from")
	addIPv6FiltersURL := flag.String("addIPv6FiltersURL", "http://192.168.0.1/rest/v1/network/ipv6/ipportfilters", "URL to add IPv6 filters to")
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
		Timeout: time.Second * 20,
	}

	// ? This default IPv6 is made up, it will be overwritten
	previousIPv6 := *previousIPv6Flag

	// ! Should implement graceful shutdown but it's probably fine
	for {
		slog.Info("Sleeping for 10 seconds")
		time.Sleep(time.Duration(*sleepTime) * time.Second)

		// TODO: Handle IPv4 better than exit-ing
		slog.Info("Fetching IPv6 address", slog.String("ipv6URL", *ipv6URL))
		newIPv6, err := getIPv6(httpClient, *ipv6URL)
		if err != nil {
			slog.Error(err.Error())
			slog.Error("virgin-auto-firewall failed to get IPv6, restarting loop")
			continue
		}

		slog.Info("Fetched IPv6 successfully", slog.String("IPv6", newIPv6))

		if newIPv6 == previousIPv6 {
			slog.Info("IPv6 has not changed", slog.String("IPv6", newIPv6))
			continue
		}

		slog.Info("IPv6 has changed", slog.String("previousIPv6", previousIPv6), slog.String("newIPv6", newIPv6))

		slog.Info("Attempting to login", slog.String("loginURL", *loginURL), slog.String("routerPassword", *routerPassword))
		userId, bearerToken, loginErr := login(httpClient, *loginURL, *routerPassword)
		if loginErr != nil {
			slog.Error(loginErr.Error())
			slog.Error("virgin-auto-firewall failed to login, restarting loop")
			continue
		}

		// ! If logged in successfully, it is essential to log out or nobody else can log in
		slog.Info("Logged in successfully", slog.String("bearerToken", bearerToken))

		if *checkConnected {
			// ! This can take a while, average of 10s for ~15 devices
			slog.Info("Attempting to get connected devices", slog.String("devicesURL", *devicesURL), slog.String("bearerToken", bearerToken))
			devices, devicesErr := getConnectedDevices(httpClient, *devicesURL, bearerToken)
			if devicesErr != nil {
				slog.Error(devicesErr.Error())
				slog.Error("virgin-auto-firewall failed to get connected devices, attempting logout and restarting loop")
				quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
				f1.Close()
				continue
			}

			slog.Info("Got connected devices successfully", slog.Int("numDevices", len(*devices.Hosts.Hosts)))

			// ? Check if IPv6 is in connected devices, maybe device still listed using old IPv6
			slog.Info("Checking if IPv6 is in connected devices", slog.String("IPv6", newIPv6))
			deviceIdx := -1

			for i := range *devices.Hosts.Hosts {
				if (*devices.Hosts.Hosts)[i].Config.Ipv6.GlobalAddress == newIPv6 {
					deviceIdx = i
					break
				}
			}

			if deviceIdx == -1 {
				slog.Info("IPv6 is not in connected devices", slog.String("IPv6", newIPv6))
				slog.Info("virgin-auto-firewall attempting logout and restarting loop")
				quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
				f1.Close()
				continue
			}

			slog.Info("IPv6 is in connected devices", slog.Int("deviceIdx", deviceIdx), slog.String("IPv6", newIPv6), slog.String("macAddress", (*devices.Hosts.Hosts)[deviceIdx].MacAddress), slog.String("hostname", (*devices.Hosts.Hosts)[deviceIdx].Config.Hostname))
		}

		slog.Info("Attempting to get IPv6 info", slog.String("ipv6InfoURL", *ipv6InfoURL), slog.String("bearerToken", bearerToken))
		ipv6Info, ipv6InfoErr := getNetworkIPv6Info(httpClient, *ipv6InfoURL, bearerToken)
		if ipv6InfoErr != nil {
			slog.Error(ipv6InfoErr.Error())
			slog.Error("virgin-auto-firewall failed to get IPv6 info, attempting logout and restarting loop")
			quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
			f1.Close()
			continue
		}

		slog.Info("Got IPv6 info successfully", slog.String("lanNetworkPrefixAddress", *ipv6Info.Info.LanNetworkPrefixAddress))

		slog.Info("Checking if IPv6 contains network prefix", slog.String("IPv6", newIPv6), slog.String("lanNetworkPrefixAddress", *ipv6Info.Info.LanNetworkPrefixAddress))

		// ? Check if IPv6 contains network prefix, otherwise we can't create a firewall rule
		// ? Remove trailing colon from network prefix e.g. 1325:8084:3a23:fe80::
		if !strings.Contains(newIPv6, strings.TrimSuffix(*ipv6Info.Info.LanNetworkPrefixAddress, ":")) {
			slog.Error("IPv6 does not contain network prefix", slog.String("IPv6", newIPv6), slog.String("lanNetworkPrefixAddress", *ipv6Info.Info.LanNetworkPrefixAddress))
			slog.Error("virgin-auto-firewall attempting logout and restarting loop")
			quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
			f1.Close()
			continue
		}

		slog.Info("IPv6 contains network prefix", slog.String("IPv6", newIPv6), slog.String("lanNetworkPrefixAddress", *ipv6Info.Info.LanNetworkPrefixAddress))

		slog.Info("Attempting to get port filters", slog.String("portFiltersURL", *portFiltersURL), slog.String("bearerToken", bearerToken))
		filters, filtersErr := getPortFilters(httpClient, *portFiltersURL, bearerToken)
		if filtersErr != nil {
			slog.Error(filtersErr.Error())
			slog.Error("virgin-auto-firewall failed to get port filters, attempting logout and restarting loop")
			quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
			f1.Close()
			continue
		}

		slog.Info("Got port filters successfully", slog.Int("numFilters", len(*filters.Ipportfilters.Ipv6.Rules)))

		slog.Info("Checking if there is a filter for the previous IPv6", slog.String("previousIPv6", previousIPv6))
		previousIPv6FilterIdx := -1

		for i := range *filters.Ipportfilters.Ipv6.Rules {
			if (*filters.Ipportfilters.Ipv6.Rules)[i].Filter.DestinationStartAddress == previousIPv6 {
				previousIPv6FilterIdx = i
				break
			}
		}

		if previousIPv6FilterIdx != -1 {
			slog.Info("There is a filter for the previous IPv6", slog.Int("previousIPv6FilterIdx", previousIPv6FilterIdx), slog.String("previousIPv6", previousIPv6), slog.String("destinationStartAddress", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.DestinationStartAddress), slog.String("protocol", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Protocol), slog.String("direction", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Direction))
			slog.Info("Attempting to delete filter for the previous IPv6", slog.String("previousIPv6", previousIPv6), slog.String("destinationStartAddress", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.DestinationStartAddress), slog.String("protocol", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Protocol), slog.String("direction", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Direction))
			deleteErr := deletePortFilter(httpClient, fmt.Sprintf(*deleteIPv6FiltersURL, (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].ID), bearerToken)
			if deleteErr != nil {
				slog.Error(deleteErr.Error())
				slog.Error("virgin-auto-firewall failed to delete filter for the previous IPv6, attempting logout and restarting loop")
				quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
				f1.Close()
				continue
			}
			slog.Info("Deleted filter for the previous IPv6 successfully", slog.String("previousIPv6", previousIPv6), slog.String("destinationStartAddress", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.DestinationStartAddress), slog.String("protocol", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Protocol), slog.String("direction", (*filters.Ipportfilters.Ipv6.Rules)[previousIPv6FilterIdx].Filter.Direction))
		} else {
			slog.Info("There is no filter for the previous IPv6", slog.String("previousIPv6", previousIPv6))
		}

		slog.Info("Checking if there is a filter for the new IPv6", slog.String("newIPv6", newIPv6))
		newIPv6FilterIdx := -1

		for i := range *filters.Ipportfilters.Ipv6.Rules {
			if (*filters.Ipportfilters.Ipv6.Rules)[i].Filter.DestinationStartAddress == newIPv6 {
				newIPv6FilterIdx = i
				break
			}
		}

		if newIPv6FilterIdx != -1 {
			slog.Info("There is an existing filter for the new IPv6", slog.Int("newIPv6FilterIdx", newIPv6FilterIdx), slog.String("newIPv6", newIPv6), slog.String("destinationStartAddress", (*filters.Ipportfilters.Ipv6.Rules)[newIPv6FilterIdx].Filter.DestinationStartAddress), slog.String("protocol", (*filters.Ipportfilters.Ipv6.Rules)[newIPv6FilterIdx].Filter.Protocol), slog.String("direction", (*filters.Ipportfilters.Ipv6.Rules)[newIPv6FilterIdx].Filter.Direction))
			slog.Info("virgin-auto-firewall attempting logout and restarting loop")
			previousIPv6 = newIPv6
			quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
			f1.Close()
			continue
		}

		slog.Info("There is no filter for the new IPv6", slog.String("newIPv6", newIPv6))
		slog.Info("Attempting to create filter for the new IPv6", slog.String("newIPv6", newIPv6))
		addFilterResponse1, addFilterErr := addPortFilter(httpClient, *addIPv6FiltersURL, newIPv6, bearerToken)
		if addFilterErr != nil {
			slog.Error(addFilterErr.Error())
			slog.Error("virgin-auto-firewall failed to create filter for the new IPv6, attempting logout and restarting loop")
			quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
			f1.Close()
			continue
		}

		slog.Info("Created filter for the new IPv6 successfully", slog.Int("id", *addFilterResponse1.Created.ID), slog.String("uri", addFilterResponse1.Created.URI), slog.String("newIPv6", newIPv6))
		previousIPv6 = newIPv6

		quickLogout(httpClient, fmt.Sprintf(*logoutURL, userId, bearerToken), bearerToken)
	}
}
