package sockets

import (
	"net/http"
	"net/url"
	"testing"
)

const (
	httpProxy  = "http://proxy.example.com"
	httpsProxy = "https://proxy.example.com"
)

func TestConfigureTransportProxy(t *testing.T) {
	// roughly based on defaultHTTPClient in the docker client
	u := &url.URL{
		Scheme: "tcp",
		Host:   "docker.acme.example.com",
	}
	transport := new(http.Transport)
	err := ConfigureTransport(transport, u.Scheme, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", httpProxy)
	t.Setenv("HTTPS_PROXY", httpsProxy)

	request, err := http.NewRequest(http.MethodGet, "tcp://docker.acme.example.com:2376", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, err := transport.Proxy(request)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL.String() != httpProxy {
		t.Fatalf("expected %s, got %s", httpProxy, proxyURL)
	}
}

func TestTCPProxyFromEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", httpProxy)
	t.Setenv("HTTPS_PROXY", httpsProxy)

	tests := []struct {
		url      string
		expected string
	}{
		{
			url:      "tcp://example.com:2376",
			expected: httpProxy,
		},
		{
			url:      "http://example.com:2375",
			expected: httpProxy,
		},
		{
			url:      "https://example.com:2376",
			expected: httpsProxy,
		},
	}

	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}

			proxyURL, err := TCPProxyFromEnvironment(request)
			if err != nil {
				t.Fatal(err)
			}
			if tc.expected == "" {
				if proxyURL != nil {
					t.Fatalf("expected no proxy, got %s", proxyURL)
				}
			} else if proxyURL.String() != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, proxyURL)
			}
		})
	}
}
