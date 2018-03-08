// Package tlsconfig provides primitives to retrieve secure-enough TLS configurations for both clients and servers.
//
// As a reminder from https://golang.org/pkg/crypto/tls/#Config:
//	A Config structure is used to configure a TLS client or server. After one has been passed to a TLS function it must not be modified.
//	A Config may be reused; the tls package will also not modify it.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

// PEMSource represents a provider of some PEM Block
type PEMSource interface {
	Data() ([]byte, error)
	Name() string
}

// PEMFile is a PEMSource backed by a file
type PEMFile string

// Data returns PEM data from the file
func (f PEMFile) Data() ([]byte, error) {
	return ioutil.ReadFile(string(f))
}

// Name returns the name of the file
func (f PEMFile) Name() string {
	return string(f)
}

// PEMInMemory is a PEMSource from memory
type PEMInMemory []byte

// Data returns PEM data from memory
func (m PEMInMemory) Data() ([]byte, error) {
	return []byte(m), nil
}

// Name returns <in memory>
func (m PEMInMemory) Name() string {
	return "<in memory>"
}

// Options represents the information needed to create client and server TLS configurations.
type Options struct {
	CA PEMSource

	// If either Cert or Key is nil, Client() will not load them
	// preventing the client from authenticating to the server.
	// However, Server() requires them and will error out if they are empty.
	Cert PEMSource
	Key  PEMSource

	// client-only option
	InsecureSkipVerify bool
	// server-only option
	ClientAuth tls.ClientAuthType
	// If ExclusiveRootPools is set, then if a CA file is provided, the root pool used for TLS
	// creds will include exclusively the roots in that CA file.  If no CA file is provided,
	// the system pool will be used.
	ExclusiveRootPools bool
	MinVersion         uint16
	// If Passphrase is set, it will be used to decrypt a TLS private key
	// if the key is encrypted
	Passphrase string
}

// Extra (server-side) accepted CBC cipher suites - will phase out in the future
var acceptedCBCCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
}

// DefaultServerAcceptedCiphers should be uses by code which already has a crypto/tls
// options struct but wants to use a commonly accepted set of TLS cipher suites, with
// known weak algorithms removed.
var DefaultServerAcceptedCiphers = append(clientCipherSuites, acceptedCBCCiphers...)

// allTLSVersions lists all the TLS versions and is used by the code that validates
// a uint16 value as a TLS version.
var allTLSVersions = map[uint16]struct{}{
	tls.VersionSSL30: {},
	tls.VersionTLS10: {},
	tls.VersionTLS11: {},
	tls.VersionTLS12: {},
}

// ServerDefault returns a secure-enough TLS configuration for the server TLS configuration.
func ServerDefault(ops ...func(*tls.Config)) *tls.Config {
	tlsconfig := &tls.Config{
		// Avoid fallback by default to SSL protocols < TLS1.2
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites:             DefaultServerAcceptedCiphers,
	}

	for _, op := range ops {
		op(tlsconfig)
	}

	return tlsconfig
}

// ClientDefault returns a secure-enough TLS configuration for the client TLS configuration.
func ClientDefault(ops ...func(*tls.Config)) *tls.Config {
	tlsconfig := &tls.Config{
		// Prefer TLS1.2 as the client minimum
		MinVersion:   tls.VersionTLS12,
		CipherSuites: clientCipherSuites,
	}

	for _, op := range ops {
		op(tlsconfig)
	}

	return tlsconfig
}

// certPool returns an X.509 certificate pool from `caFile`, the certificate file.
func certPool(ca PEMSource, exclusivePool bool) (*x509.CertPool, error) {
	if ca == nil {
		return nil, fmt.Errorf("no CA PEM data")
	}
	// If we should verify the server, we need to load a trusted ca
	var (
		certPool *x509.CertPool
		err      error
	)
	if exclusivePool {
		certPool = x509.NewCertPool()
	} else {
		certPool, err = SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to read system certificates: %v", err)
		}
	}
	pem, err := ca.Data()
	if err != nil {
		return nil, fmt.Errorf("could not read CA certificate %q: %v", ca.Name(), err)
	}
	if !certPool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to append certificates from PEM file: %q", ca.Name())
	}
	return certPool, nil
}

// isValidMinVersion checks that the input value is a valid tls minimum version
func isValidMinVersion(version uint16) bool {
	_, ok := allTLSVersions[version]
	return ok
}

// adjustMinVersion sets the MinVersion on `config`, the input configuration.
// It assumes the current MinVersion on the `config` is the lowest allowed.
func adjustMinVersion(options Options, config *tls.Config) error {
	if options.MinVersion > 0 {
		if !isValidMinVersion(options.MinVersion) {
			return fmt.Errorf("Invalid minimum TLS version: %x", options.MinVersion)
		}
		if options.MinVersion < config.MinVersion {
			return fmt.Errorf("Requested minimum TLS version is too low. Should be at-least: %x", config.MinVersion)
		}
		config.MinVersion = options.MinVersion
	}

	return nil
}

// IsErrEncryptedKey returns true if the 'err' is an error of incorrect
// password when tryin to decrypt a TLS private key
func IsErrEncryptedKey(err error) bool {
	return errors.Cause(err) == x509.IncorrectPasswordError
}

// getPrivateKey returns the private key in 'keyBytes', in PEM-encoded format.
// If the private key is encrypted, 'passphrase' is used to decrypted the
// private key.
func getPrivateKey(keyBytes []byte, passphrase string) ([]byte, error) {
	// this section makes some small changes to code from notary/tuf/utils/x509.go
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("no valid private key found")
	}

	var err error
	if x509.IsEncryptedPEMBlock(pemBlock) {
		keyBytes, err = x509.DecryptPEMBlock(pemBlock, []byte(passphrase))
		if err != nil {
			return nil, errors.Wrap(err, "private key is encrypted, but could not decrypt it")
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: pemBlock.Type, Bytes: keyBytes})
	}

	return keyBytes, nil
}

// getCert returns a Certificate from the CertFile and KeyFile in 'options',
// if the key is encrypted, the Passphrase in 'options' will be used to
// decrypt it.
func getCert(options Options) ([]tls.Certificate, error) {
	if options.Cert == nil && options.Key == nil {
		return nil, nil
	}
	if options.Cert == nil {
		return nil, errors.New("cert is missing")
	}
	if options.Key == nil {
		return nil, errors.New("key is missing")
	}

	errMessage := "Could not load X509 key pair"

	cert, err := options.Cert.Data()
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	prKeyBytes, err := options.Key.Data()
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	prKeyBytes, err = getPrivateKey(prKeyBytes, options.Passphrase)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	tlsCert, err := tls.X509KeyPair(cert, prKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	return []tls.Certificate{tlsCert}, nil
}

// Client returns a TLS configuration meant to be used by a client.
func Client(options Options) (*tls.Config, error) {
	tlsConfig := ClientDefault()
	tlsConfig.InsecureSkipVerify = options.InsecureSkipVerify
	if !options.InsecureSkipVerify && options.CA != nil {
		CAs, err := certPool(options.CA, options.ExclusiveRootPools)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = CAs
	}

	tlsCerts, err := getCert(options)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = tlsCerts

	if err := adjustMinVersion(options, tlsConfig); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

// Server returns a TLS configuration meant to be used by a server.
func Server(options Options) (*tls.Config, error) {
	tlsConfig := ServerDefault()
	tlsConfig.ClientAuth = options.ClientAuth
	if options.Cert == nil {
		return nil, errors.New("cert is missing")
	}
	if options.Key == nil {
		return nil, errors.New("key is missing")
	}
	cert, err := options.Cert.Data()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("Could not load X509 key pair (cert: %q, key: %q): %v", options.Cert.Name(), options.Key.Name(), err)
		}
		return nil, fmt.Errorf("could not read cert data: %s", err)
	}
	key, err := options.Key.Data()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("Could not load X509 key pair (cert: %q, key: %q): %v", options.Cert.Name(), options.Key.Name(), err)
		}
		return nil, fmt.Errorf("could not read key data: %s", err)
	}
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("Error reading X509 key pair (cert: %q, key: %q): %v. Make sure the key is not encrypted.", options.Cert.Name(), options.Key.Name(), err)
	}
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	if options.ClientAuth >= tls.VerifyClientCertIfGiven && options.CA != nil {
		CAs, err := certPool(options.CA, options.ExclusiveRootPools)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = CAs
	}

	if err := adjustMinVersion(options, tlsConfig); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}
