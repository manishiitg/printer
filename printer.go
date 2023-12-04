package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// UNIX Time is faster and smaller than most timestamps
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	ipMacMap, ipRangeMap, _ := runARP()
	// Print the IP and MAC addresses
	for ip, mac := range ipMacMap {
		log.Info().Msgf("IP: %s, MAC: %s\n", ip, mac)
	}

	// Print the IP ranges
	for ipRange := range ipRangeMap {
		log.Info().Msgf("IP Range: %s\n", ipRange)
	}

	// Now you can use these IP addresses for further scanning with Nmap
	log.Info().Msgf("Network IP ranges found:")
	for ipRange := range ipRangeMap {
		if strings.Contains(ipRange, "192.168") {
			log.Info().Msgf("scanning %s", ipRange)

			// Now you can run Nmap on the network range
			nmapCmd := exec.Command("nmap", "-p", "9100", ipRange)
			var nmapOut bytes.Buffer
			nmapCmd.Stdout = &nmapOut
			if err := nmapCmd.Run(); err != nil {
				log.Error().Err(err).Msgf("Error executing Nmap on network range %s: \n. Download from https://nmap.org/download", ipRange)
				continue
			}

			// Parse the Nmap output to find open IP addresses
			nmapScanner := bufio.NewScanner(&nmapOut)
			ipFound := ""
			for nmapScanner.Scan() {
				nmapLine := nmapScanner.Text()
				// fmt.Println("debug nmap", nmapLine)

				ipRegex := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
				if ipMatches := ipRegex.FindStringSubmatch(nmapLine); ipMatches != nil {
					ipFound = ipMatches[0]
				}
				if strings.Contains(nmapLine, "open") {
					log.Info().Msgf("Printer IP: %s", ipFound)
					if mac, ok := ipMacMap[ipFound]; ok {
						log.Info().Msgf("Printer IP Mac: %s --> %s", ipFound, mac)
						sendRequest([]string{mac}, []string{ipFound})
					} else {
						nmapEcho(ipFound)
						log.Debug().Msgf("printer ip not found doing arp again!")
						ipMacMap, ipRangeMap, _ = runARP()
						if mac, ok := ipMacMap[ipFound]; ok {
							log.Info().Msgf("Printer IP Mac: %s --> %s", ipFound, mac)
							sendRequest([]string{mac}, []string{ipFound})
						} else {
							mac, err := getMacAddr(net.ParseIP(ipFound))
							if err != nil {
								log.Error().Err(err).Msgf("unable to find mac for ip %s", ipFound)
							} else {
								log.Info().Msgf("Printer IP: %s --> %s", ipFound, mac)
								sendRequest([]string{mac.String()}, []string{ipFound})
							}
						}
					}
				} else {
					log.Debug().Msgf("ip found but not printer %s", ipFound)
				}

			}

			if err := nmapScanner.Err(); err != nil {
				log.Error().Err(err).Msgf("Error scanning Nmap output:")
			}
		}
	}

	// if err := scanner.Err(); err != nil {
	// 	fmt.Println("Error scanning arp output:", err)
	// }
}

func runARP() (map[string]string, map[string]bool, error) {
	cmd := exec.Command("arp", "-a")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	// Start the command
	err := cmd.Start()
	if err != nil {
		log.Error().Err(err).Msg("Error starting arp:")
		return nil, nil, err
	}

	// Create a scanner to read the command's output
	scanner := bufio.NewScanner(&out)

	// Start a goroutine to read and print the command's output
	go func() {
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	// Wait for the command to finish
	err = cmd.Wait()
	if err != nil {
		log.Error().Err(err).Msg("Error waiting for arp:")
		return nil, nil, err
	}

	// Regular expression to match IP and MAC addresses in arp output
	ipMacRegex := regexp.MustCompile(`^([0-9.]+)\s+([0-9A-Fa-f:-]+)`)

	ipMacMap := make(map[string]string)
	ipRangeMap := make(map[string]bool)

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		fmt.Println("line")
		if ipMacMatches := ipMacRegex.FindStringSubmatch(line); ipMacMatches != nil {
			ip := ipMacMatches[1]
			mac := ipMacMatches[2]
			ipMacMap[ip] = mac

			ipParts := strings.Split(ip, ".")
			networkIPRange := fmt.Sprintf("%s.%s.%s.0/24", ipParts[0], ipParts[1], ipParts[2])
			ipRangeMap[networkIPRange] = true
		}
	}
	return ipMacMap, ipRangeMap, nil
}

func getMacAddr(ip net.IP) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return iface.HardwareAddr, nil
			}
		}
	}

	return nil, fmt.Errorf("no network interface found for IP %s", ip)
}

type RequestData struct {
	MacAddress []string `json:"mac_address"`
	IPAddress  []string `json:"ip_address"`
}

func sendRequest(macAddress []string, ipAddress []string) error {
	url := "https://wms.staging-dev.citymall.dev/wms-app/commons/mac-ip-address-mapping"
	data := RequestData{
		MacAddress: macAddress,
		IPAddress:  ipAddress,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)
	return nil
}

func nmapEcho(ip string) {
	cmd := exec.Command("nmap", "-sn", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + string(out))
		return
	}
	fmt.Println(string(out))
}
