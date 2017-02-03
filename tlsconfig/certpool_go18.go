// +build go1.8

package tlsconfig

import "crypto/x509"

// SystemCertPool returns the system cert pool
func SystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}
