package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// List of vulnerable indicators
var vulnerableIndicators = []string{
	"No resources found",
	"404 Not Found",
	"Website not configured",
	"This resource is not available",
	"The requested site does not exist",
	"Your app is ready to go!",
	"GitHub",
	"Domain not found",
	"Error 404",
	"Unknown domain",
	"Site not found",
  // More to be added
}

// Worker function to process subdomains
func worker(ctx context.Context, subdomains <-chan string, externalServices map[string]struct{}, results chan<- string, wg *sync.WaitGroup, verbose, check bool, timeout time.Duration) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			if verbose {
				fmt.Println("[INFO] Worker shutting down")
			}
			return
		case subdomain, ok := <-subdomains:
			if !ok {
				return
			}

			time.Sleep(delayBetweenRequests)
			cleanedSubdomain := strings.TrimPrefix(strings.TrimPrefix(subdomain, "http://"), "https://")
			cname, err := lookupCNAME(ctx, cleanedSubdomain, timeout)
			if err != nil {
				if verbose {
					fmt.Printf("[NO CNAME] %s: %v\n", cleanedSubdomain, err)
				}
				continue
			}

			vulnerable := false
			for extService := range externalServices {
				if strings.HasSuffix(cname, extService) {
					vulnerable = true
					break
				}
			}

			if vulnerable {
				if check && checkServiceVulnerability(cleanedSubdomain, verbose) {
					results <- fmt.Sprintf("[VULNERABLE] %s -> %s", cleanedSubdomain, cname)
				} else if !check {
					results <- fmt.Sprintf("[POTENTIALLY VULNERABLE] %s -> %s", cleanedSubdomain, cname)
				} else if verbose {
					results <- fmt.Sprintf("[SAFE] %s -> %s (Not exploitable)", cleanedSubdomain, cname)
				}
			} else if verbose {
				results <- fmt.Sprintf("[SAFE] %s -> %s", cleanedSubdomain, cname)
			}
		}
	}
}

// Lookup CNAME with context and timeout
func lookupCNAME(ctx context.Context, subdomain string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, subdomain)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(cname, "."), nil
}

// Check if the service is actually vulnerable
func checkServiceVulnerability(subdomain string, verbose bool) bool {
	url := fmt.Sprintf("https://%s", subdomain)
	resp, err := http.Get(url)
	if err != nil {
		if verbose {
			fmt.Printf("[ERROR] Failed to fetch %s: %v\n", url, err)
		}
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if verbose {
			fmt.Printf("[ERROR] Failed to read response body for %s: %v\n", url, err)
		}
		return false
	}

	bodyStr := strings.ToLower(string(body))
	for _, indicator := range vulnerableIndicators {
		if strings.Contains(bodyStr, strings.ToLower(indicator)) {
			if verbose {
				fmt.Printf("[DEBUG] Found vulnerable indicator '%s' in %s\n", indicator, subdomain)
			}
			return true
		}
	}

	if verbose {
		fmt.Printf("[DEBUG] No vulnerable indicators found for %s\n", subdomain)
	}
	return false
}

func loadExternalServices(file string) (map[string]struct{}, error) {
	services := make(map[string]struct{})
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		service := strings.TrimSpace(scanner.Text())
		if service != "" {
			services[service] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
  

	return services, nil
}
