// These helpers provide a deterministic replacement for x509.SystemCertPool
// in tests.
//
// On macOS and Windows, crypto/x509 may delegate certificate verification to
// platform APIs, and the system pool is not a simple in-memory set of roots.
// As a result, tests that rely on SystemCertPool can exhibit OS-dependent
// behavior.
//
// To avoid this, tests inject a synthetic "system" pool backed by generated
// certificates. This ensures consistent behavior across platforms and allows
// precise control over trusted roots when testing root-pool composition logic.
package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"
)

type testTrustRoot struct {
	RootPEM  []byte            // PEM-encoded fake root CA.
	RootCert *x509.Certificate // Parsed fake root CA.
	Pool     *x509.CertPool    // Pool containing RootCert.
	LeafPEM  []byte            // PEM-encoded cert signed by RootCert.
	LeafCert *x509.Certificate // Parsed cert trusted by the fake root.
}

func newTestTrustRoot() (*testTrustRoot, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	rootSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "fake system root",
			Organization: []string{"tlsconfig tests"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDER,
	})

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootPEM); !ok {
		return nil, errors.New("failed to append fake root")
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	leafSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName: "fake system leaf",
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafDER,
	})

	return &testTrustRoot{
		RootPEM:  rootPEM,
		RootCert: rootCert,
		Pool:     pool,
		LeafPEM:  leafPEM,
		LeafCert: leafCert,
	}, nil
}

var fakeSystemRootData = sync.OnceValues(func() (*testTrustRoot, error) {
	return newTestTrustRoot()
})

func systemRootTrustedX509() (*x509.Certificate, error) {
	root, err := fakeSystemRootData()
	if err != nil {
		return nil, err
	}
	return root.LeafCert, nil
}

func fakeSystemCertPool() func() (*x509.CertPool, error) {
	return func() (*x509.CertPool, error) {
		root, err := fakeSystemRootData()
		if err != nil {
			return nil, err
		}
		return root.Pool.Clone(), nil
	}
}
