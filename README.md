# forging passkeys - go

A Go implementation of the "Forging Passkeys" research demonstrating virtual FIDO2/WebAuthn authenticators for educational and authorized security testing purposes.

## Research Credit

This implementation is based on the excellent research **"Forging Passkeys: Exploring the FIDO2 / WebAuthn Attack Surface"** by [@vmfunc](https://twitter.com/vmfunc).

**Original Research**: https://www.nullpt.rs/forging-passkeys

The original work provides comprehensive analysis of CTAP2 protocol internals, WebAuthn security boundaries, and browser implementation details. This Go implementation demonstrates the core concepts from that research.

## What This Demonstrates

This proof-of-concept shows how Chrome's Virtual Authenticator environment can be used to create software-only FIDO2 authenticators that bypass typical WebAuthn flows. Key features include:

- **Virtual CTAP2 Implementation**: Complete software implementation of CTAP2 protocol
- **Chrome DevTools Integration**: Uses Chrome's debugging APIs to inject virtual authenticators  
- **Realistic Behavior Simulation**: Mimics hardware authenticator characteristics including:
  - Non-zero initial sign counters (attempts to bypass zero-counter detection)
  - Variable sign counter increments (simulates real hardware behavior)
  - Realistic processing delays
  - Hardware-like serial numbers and firmware versions

## Technical Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│ Chrome DevTools  │◄──►│ Virtual         │
│   (WebAuthn)    │    │ Protocol (CDP)   │    │ Authenticator   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │ CTAP2 Protocol  │
                                               │ Implementation  │
                                               └─────────────────┘
```

## Usage

```bash
# Build the application
go build -o authenticator cmd/authenticator/main.go

# Run with visible Chrome window
./authenticator -rpid="webauthn.io" -url="https://webauthn.io"

# Run in headless mode
./authenticator -headless=true -rpid="example.com" -url="https://example.com"
```

### Command Line Options

- `-rpid` - Relying Party ID (website domain)
- `-url` - Target URL to navigate to  
- `-headless` - Run Chrome in headless mode (default: false)

## Educational Value

This implementation helps security researchers and developers understand:

- CTAP2 protocol implementation details
- WebAuthn browser API integration
- Virtual authenticator capabilities and limitations
- Sign counter behavior in hardware authenticators
- Chrome DevTools Protocol usage for WebAuthn testing

## Defensive Considerations

The original research identifies several mitigations that websites and browsers can implement:

- **Sign Counter Validation**: Reject credentials with suspicious counter behavior
- **Attestation Verification**: Validate authenticator attestation chains
- **Rate Limiting**: Limit credential registrations per IP/session
- **AAGUID Whitelisting**: Only allow known hardware authenticator types
- **Browser Mitigations**: Restrict virtual authenticator APIs to development contexts

## Legal and Ethical Use

**IMPORTANT DISCLAIMER**

This tool is intended for:
- Educational purposes and security research
- Authorized penetration testing with explicit permission
- Testing your own applications and systems
- Understanding WebAuthn implementation details

This tool should **NOT** be used for:
- Unauthorized access to systems you don't own
- Circumventing security controls without permission
- Any illegal activities

Users are solely responsible for ensuring their use complies with applicable laws and regulations.

## Contributing

This is an educational implementation. If you find issues or have improvements, please feel free to submit pull requests or issues.

## Acknowledgments

- **[@vmfunc](https://twitter.com/vmfunc)** for the original groundbreaking research
- **[nullpt.rs](https://www.nullpt.rs/forging-passkeys)** for the comprehensive technical writeup
- The WebAuthn and FIDO Alliance communities for their work on authentication standards

## License

This project is provided for educational purposes. Please review the original research and respect the intellectual property of the original authors. 