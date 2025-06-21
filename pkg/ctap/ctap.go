package ctap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	CTAP2_MAKE_CREDENTIAL = 0x01
	CTAP2_GET_ASSERTION   = 0x02
	CTAP2_GET_INFO        = 0x04
	CTAP2_CLIENT_PIN      = 0x06
	CTAP2_RESET           = 0x07
)

const (
	CTAP2_OK                 = 0x00
	CTAP2_ERR_INVALID_COMMAND = 0x01
	CTAP2_ERR_CBOR_PARSING   = 0x10
	CTAP2_ERR_NO_CREDENTIALS = 0x2E
)

const ES256 = -7

type COSEKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type MakeCredentialRequest struct {
	ClientDataHash []byte                 `cbor:"1,keyasint"`
	RP             map[string]interface{} `cbor:"2,keyasint"`
	User           map[string]interface{} `cbor:"3,keyasint"`
	PubKeyCredParams []map[string]interface{} `cbor:"4,keyasint"`
	ExcludeList    []map[string]interface{} `cbor:"5,keyasint,omitempty"`
	Extensions     map[string]interface{} `cbor:"6,keyasint,omitempty"`
	Options        map[string]interface{} `cbor:"7,keyasint,omitempty"`
	PinAuth        []byte                 `cbor:"8,keyasint,omitempty"`
	PinProtocol    int                    `cbor:"9,keyasint,omitempty"`
}

type GetAssertionRequest struct {
	RPID           string                   `cbor:"1,keyasint"`
	ClientDataHash []byte                   `cbor:"2,keyasint"`
	AllowList      []map[string]interface{} `cbor:"3,keyasint,omitempty"`
	Extensions     map[string]interface{}   `cbor:"4,keyasint,omitempty"`
	Options        map[string]interface{}   `cbor:"5,keyasint,omitempty"`
	PinAuth        []byte                   `cbor:"6,keyasint,omitempty"`
	PinProtocol    int                      `cbor:"7,keyasint,omitempty"`
}

type Credential struct {
	ID         []byte
	PrivateKey *ecdsa.PrivateKey
	RPID       string
	UserID     []byte
	SignCount  uint32
	CreatedAt  time.Time
}

type Authenticator struct {
	AAGUID      [16]byte
	credentials map[string]*Credential
	serialNumber string
	firmwareVersion string
	lastUsed    time.Time
}

func NewAuthenticator() *Authenticator {
	auth := &Authenticator{
		AAGUID:      [16]byte{},
		credentials: make(map[string]*Credential),
		serialNumber: generateRealisticSerialNumber(),
		firmwareVersion: generateRealisticFirmwareVersion(),
		lastUsed:    time.Now(),
	}
	
	log.Printf("[+] virtual hardware simulation:")
	log.Printf("[-]  serial: %s", auth.serialNumber)
	log.Printf("[-]  firmware: %s", auth.firmwareVersion)
	log.Printf("[-]  aaguid: %x (null - appears as generic authenticator)", auth.AAGUID)
	
	return auth
}

func (a *Authenticator) StoreCredential(rpid string, cred *Credential) {
	a.credentials[rpid] = cred
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MarshalPKCS8PrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	return der, nil
}

func (a *Authenticator) HandleCommand(cmd byte, reqData []byte) ([]byte, error) {
	switch cmd {
	case CTAP2_MAKE_CREDENTIAL:
		return a.handleMakeCredential(reqData)
	case CTAP2_GET_ASSERTION:
		return a.handleGetAssertion(reqData)
	case CTAP2_GET_INFO:
		return a.handleGetInfo()
	default:
		return []byte{CTAP2_ERR_INVALID_COMMAND}, nil
	}
}

func (a *Authenticator) handleMakeCredential(reqData []byte) ([]byte, error) {
	var req MakeCredentialRequest
	if err := cbor.Unmarshal(reqData, &req); err != nil {
		return []byte{CTAP2_ERR_CBOR_PARSING}, nil
	}

	a.simulateHardwareDelay("registration")

	rpid, ok := req.RP["id"].(string)
	if !ok {
		return []byte{CTAP2_ERR_CBOR_PARSING}, nil
	}

	userID, ok := req.User["id"].([]byte)
	if !ok {
		return []byte{CTAP2_ERR_CBOR_PARSING}, nil
	}

	privateKey, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("failed to generate credential ID: %w", err)
	}

	cred := &Credential{
		ID:         credID,
		PrivateKey: privateKey,
		RPID:       rpid,
		UserID:     userID,
		SignCount:  a.generateRealisticInitialSignCount(),
		CreatedAt:  time.Now(),
	}
	a.credentials[rpid] = cred

	authData, err := a.buildAuthenticatorData(rpid, true, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to build authenticator data: %w", err)
	}

	toSign := append(authData, req.ClientDataHash...)
	signature, err := a.signData(privateKey, toSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	response := map[int]interface{}{
		1: "none",
		2: authData,
		3: map[string]interface{}{"sig": signature},
	}

	responseBytes, err := cbor.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return append([]byte{CTAP2_OK}, responseBytes...), nil
}

func (a *Authenticator) handleGetAssertion(reqData []byte) ([]byte, error) {
	var req GetAssertionRequest
	if err := cbor.Unmarshal(reqData, &req); err != nil {
		return []byte{CTAP2_ERR_CBOR_PARSING}, nil
	}

	a.simulateHardwareDelay("authentication")

	cred, exists := a.credentials[req.RPID]
	if !exists {
		return []byte{CTAP2_ERR_NO_CREDENTIALS}, nil
	}

	authData, err := a.buildAuthenticatorData(req.RPID, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build authenticator data: %w", err)
	}

	oldCount := cred.SignCount
	increment := a.generateRealisticSignCountIncrement(cred)
	cred.SignCount += increment
	
	if increment == 0 {
		log.Printf("[+] sign counter: %d → %d (stuck counter - mimics hardware bug)", oldCount, cred.SignCount)
	} else if increment == 1 {
		log.Printf("[+] sign counter: %d → %d (normal increment)", oldCount, cred.SignCount)
	} else {
		log.Printf("[+] sign counter: %d → %d (+%d - mimics power cycle/internal ops)", oldCount, cred.SignCount, increment)
	}

	toSign := append(authData, req.ClientDataHash...)
	signature, err := a.signData(cred.PrivateKey, toSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	response := map[int]interface{}{
		1: cred.ID,
		2: authData,
		3: signature,
		4: cred.UserID,
	}

	responseBytes, err := cbor.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return append([]byte{CTAP2_OK}, responseBytes...), nil
}

func (a *Authenticator) handleGetInfo() ([]byte, error) {
	info := map[int]interface{}{
		1: []string{"FIDO_2_0"},           // versions
		2: []string{"credProtect"},        // extensions
		3: a.AAGUID[:],                    // aaguid
		4: map[string]interface{}{         // options
			"rk":   true,  // resident key
			"up":   true,  // user presence
			"uv":   false, // user verification
			"plat": false, // platform device
		},
		5: 1200, // maxMsgSize
		6: []int{1}, // pinProtocols
	}

	responseBytes, err := cbor.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal info response: %w", err)
	}

	return append([]byte{CTAP2_OK}, responseBytes...), nil
}

func (a *Authenticator) buildAuthenticatorData(rpid string, includeAttestation bool, cred *Credential) ([]byte, error) {
	rpidHash := sha256.Sum256([]byte(rpid))
	
	flags := byte(0x01)
	if includeAttestation {
		flags |= 0x40
	}
	
	signCount := make([]byte, 4)
	if cred != nil {
		binary.BigEndian.PutUint32(signCount, cred.SignCount)
	}

	authData := make([]byte, 0, 256)
	authData = append(authData, rpidHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, signCount...)

	if includeAttestation && cred != nil {
		authData = append(authData, a.AAGUID[:]...)
		
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(cred.ID)))
		authData = append(authData, credIDLen...)
		
		authData = append(authData, cred.ID...)
		
		pubKey, err := a.buildCOSEKey(cred.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to build COSE key: %w", err)
		}
		
		pubKeyBytes, err := cbor.Marshal(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal COSE key: %w", err)
		}
		
		authData = append(authData, pubKeyBytes...)
	}

	return authData, nil
}

func (a *Authenticator) buildCOSEKey(privateKey *ecdsa.PrivateKey) (*COSEKey, error) {
	pubKey := privateKey.PublicKey
	
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)

	return &COSEKey{
		Kty: 2,    // EC2 key type
		Alg: ES256, // ES256 algorithm
		Crv: 1,    // P-256 curve
		X:   x,
		Y:   y,
	}, nil
}

func (a *Authenticator) signData(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

func (a *Authenticator) generateRealisticInitialSignCount() uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(51))
	return uint32(n.Int64())
}

func (a *Authenticator) generateRealisticSignCountIncrement(cred *Credential) uint32 {
	age := time.Since(cred.CreatedAt)
	
	currentCount := cred.SignCount
	
	increment := uint32(1)
	
	if currentCount > 100 {
		if a.randomChance(15) {
			increment = uint32(2 + a.randomInt(4)) // 2-5
		}
	} else if age > 24*time.Hour {
		if a.randomChance(8) {
			increment = uint32(2 + a.randomInt(3)) // 2-4
		}
	}
	
	if a.randomChance(1) {
		increment = uint32(5 + a.randomInt(15)) // 5-19
	}
	
	if currentCount > 50 && a.randomChance(0.5) {
		increment = 0 // Counter doesn't increment this time
	}
	
	return increment
}

func (a *Authenticator) randomChance(percentage float64) bool {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return float64(n.Int64()) < percentage*100
}

func (a *Authenticator) randomInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func generateRealisticSerialNumber() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(90000000))
	return fmt.Sprintf("%08d", n.Int64()+10000000)
}

func generateRealisticFirmwareVersion() string {
	major := []string{"5", "6", "7"}
	minor := []int{0, 1, 2, 3, 4, 5}
	patch := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	
	majorIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(major))))
	minorIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(minor))))
	patchIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(patch))))
	
	return fmt.Sprintf("%s.%d.%d", major[majorIdx.Int64()], minor[minorIdx.Int64()], patch[patchIdx.Int64()])
}

func (a *Authenticator) simulateHardwareDelay(operation string) {
	var delay time.Duration
	
	switch operation {
	case "registration":
		delay = time.Duration(200+a.randomInt(300)) * time.Millisecond
	case "authentication":
		delay = time.Duration(50+a.randomInt(150)) * time.Millisecond
	default:
		delay = time.Duration(100+a.randomInt(100)) * time.Millisecond
	}
	
	log.Printf("[+] hardware simulation: %s delay %v (mimics real authenticator)", operation, delay)
	time.Sleep(delay)
	
	a.lastUsed = time.Now()
} 