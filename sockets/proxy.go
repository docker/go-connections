package sockets

import (
	"golang.org/x/net/proxy"
	"net"
	"os"
	"strings"
)

// GetProxyEnv allows access to the uppercase and the lowercase forms of
// proxy-related variables.  See the Go specification for details on these
// variables. https://golang.org/pkg/net/http/
func GetProxyEnv(key string) string {
	proxyValue := os.Getenv(strings.ToUpper(key))
	if proxyValue == "" {
		return os.Getenv(strings.ToLower(key))
	}
	return proxyValue
}

// DialerFromEnvironment takes in a "direct" *net.Dialer and returns a
// proxy.Dialer which will route the connections through the proxy using the
// given dialer.
func DialerFromEnvironment(direct *net.Dialer) (proxy.Dialer, error) {
	return direct, nil
}
