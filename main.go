package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var delayBetweenRequests time.Duration

func main() {
  
	subsFile := flag.String("file", "", "File containing subdomains")
	externalFile := flag.String("wordlist", "", "File containing external services")
	verbose := flag.Bool("v", false, "Enable verbose output")
	check := flag.Bool("check", false, "Enable exploitability check")
	workers := flag.Int("c", 10, "Number of concurrent workers")
	timeout := flag.Int("t", 5, "Timeout for DNS lookups in seconds")
	delay := flag.Int("d", 100, "Delay between requests in milliseconds")

	flag.Parse()

	if *subsFile == "" || *externalFile == "" {
		fmt.Println("Usage: go run main.go -file=subs.txt -wordlist=external.txt [-v] [-check] [-c=10] [-t=5] [-d=100]")
		os.Exit(1)
	}

	delayBetweenRequests = time.Duration(*delay) * time.Millisecond

	externalServices, err := loadExternalServices(*externalFile)
	if err != nil {
		fmt.Printf("Error loading external services: %v\n", err)
		os.Exit(1)
	}

	subs, err := os.Open(*subsFile)
	if err != nil {
		fmt.Printf("Error opening subdomains file: %v\n", err)
		os.Exit(1)
	}
	defer subs.Close()

	// Setup channels and wait group
	subdomains := make(chan string, *workers)
	results := make(chan string, *workers)
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\n[INFO] Received interrupt signal. Shutting down...")
		cancel()
	}()

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(ctx, subdomains, externalServices, results, &wg, *verbose, *check, time.Duration(*timeout)*time.Second)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Read subdomains and send them to workers
	go func() {
		scanner := bufio.NewScanner(subs)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				break
			case subdomains <- strings.TrimSpace(scanner.Text()):
			}
		}
		close(subdomains)
	}()

	for result := range results {
		fmt.Println(result)
	}
}
