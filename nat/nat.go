// Package nat is a convenience package for manipulation of strings describing network ports.
package nat

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PortBinding represents a binding between a Host IP address and a Host Port
type PortBinding struct {
	// HostIP is the host IP Address
	HostIP string `json:"HostIp"`
	// HostPort is the host port number
	HostPort string
}

func (pb *PortBinding) String() string {
	if pb.HostPort == "" {
		return ""
	}
	if pb.HostIP == "" {
		return pb.HostPort
	}
	return net.JoinHostPort(pb.HostIP, pb.HostPort)
}

// PortMap is a collection of PortBinding indexed by Port
type PortMap map[Port][]PortBinding

// PortSet is a collection of structs indexed by Port
type PortSet map[Port]struct{}

// Port is a string containing port number and protocol in the format "80/tcp"
type Port string

// NewPort creates a new instance of a Port given a protocol and port number or port range
func NewPort(proto, portOrRange string) (Port, error) {
	start, end, err := parsePortRange(portOrRange)
	if err != nil {
		return "", err
	}
	if start == end {
		return Port(fmt.Sprintf("%d/%s", start, proto)), nil
	}
	return Port(fmt.Sprintf("%d-%d/%s", start, end, proto)), nil
}

// ParsePort parses the port number string and returns an int
func ParsePort(rawPort string) (int, error) {
	if rawPort == "" {
		return 0, nil
	}
	port, err := parsePortNumber(rawPort)
	if err != nil {
		return 0, fmt.Errorf("invalid port '%s': %w", rawPort, err)
	}
	return port, nil
}

// ParsePortRangeToInt parses the port range string and returns start/end ints
func ParsePortRangeToInt(rawPort string) (startPort, endPort int, _ error) {
	if rawPort == "" {
		// TODO(thaJeztah): consider making this an error; this was kept to keep existing behavior.
		return 0, 0, nil
	}
	return parsePortRange(rawPort)
}

// Proto returns the protocol of a Port
func (p Port) Proto() string {
	_, proto, _ := strings.Cut(string(p), "/")
	if proto == "" {
		proto = "tcp"
	}
	return proto
}

// Port returns the port number of a Port
func (p Port) Port() string {
	port, _, _ := strings.Cut(string(p), "/")
	return port
}

// Int returns the port number of a Port as an int. It assumes [Port]
// is valid, and returns 0 otherwise.
func (p Port) Int() int {
	// We don't need to check for an error because we're going to
	// assume that any error would have been found, and reported, in [NewPort]
	port, _ := parsePortNumber(p.Port())
	return port
}

// Range returns the start/end port numbers of a Port range as ints
func (p Port) Range() (int, int, error) {
	portRange := p.Port()
	if portRange == "" {
		return 0, 0, nil
	}
	return parsePortRange(portRange)
}

// SplitProtoPort splits a port(range) and protocol, formatted as "<portnum>/[<proto>]"
// "<startport-endport>/[<proto>]". It returns an empty string for both if
// no port(range) is provided. If a port(range) is provided, but no protocol,
// the default ("tcp") protocol is returned.
//
// SplitProtoPort does not validate or normalize the returned values.
func SplitProtoPort(rawPort string) (proto string, port string) {
	port, proto, _ = strings.Cut(rawPort, "/")
	if port == "" {
		return "", ""
	}
	if proto == "" {
		proto = "tcp"
	}
	return proto, port
}

func validateProto(proto string) error {
	switch proto {
	case "tcp", "udp", "sctp":
		// All good
		return nil
	default:
		return errors.New("invalid proto: " + proto)
	}
}

// ParsePortSpecs receives port specs in the format of ip:public:private/proto and parses
// these in to the internal types
func ParsePortSpecs(ports []string) (map[Port]struct{}, map[Port][]PortBinding, error) {
	var (
		exposedPorts = make(map[Port]struct{}, len(ports))
		bindings     = make(map[Port][]PortBinding)
	)
	for _, p := range ports {
		portMappings, err := ParsePortSpec(p)
		if err != nil {
			return nil, nil, err
		}

		for _, pm := range portMappings {
			port := pm.Port
			if _, ok := exposedPorts[port]; !ok {
				exposedPorts[port] = struct{}{}
			}
			bindings[port] = append(bindings[port], pm.Binding)
		}
	}
	return exposedPorts, bindings, nil
}

// PortMapping is a data object mapping a Port to a PortBinding
type PortMapping struct {
	Port    Port
	Binding PortBinding
}

func (p *PortMapping) String() string {
	return net.JoinHostPort(p.Binding.HostIP, p.Binding.HostPort+":"+string(p.Port))
}

func splitParts(rawport string) (hostIP, hostPort, containerPort string) {
	parts := strings.Split(rawport, ":")

	switch len(parts) {
	case 1:
		return "", "", parts[0]
	case 2:
		return "", parts[0], parts[1]
	case 3:
		return parts[0], parts[1], parts[2]
	default:
		n := len(parts)
		return strings.Join(parts[:n-2], ":"), parts[n-2], parts[n-1]
	}
}

// ParsePortSpec parses a port specification string into a slice of PortMappings
func ParsePortSpec(rawPort string) ([]PortMapping, error) {
	ip, hostPort, containerPort := splitParts(rawPort)
	proto, containerPort := SplitProtoPort(containerPort)
	if containerPort == "" {
		return nil, fmt.Errorf("no port specified: %s<empty>", rawPort)
	}

	proto = strings.ToLower(proto)
	if err := validateProto(proto); err != nil {
		return nil, err
	}

	if ip != "" && ip[0] == '[' {
		// Strip [] from IPV6 addresses
		rawIP, _, err := net.SplitHostPort(ip + ":")
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %v: %w", ip, err)
		}
		ip = rawIP
	}
	if ip != "" && net.ParseIP(ip) == nil {
		return nil, errors.New("invalid IP address: " + ip)
	}

	startPort, endPort, err := parsePortRange(containerPort)
	if err != nil {
		return nil, errors.New("invalid containerPort: " + containerPort)
	}

	var startHostPort, endHostPort int
	if hostPort != "" {
		startHostPort, endHostPort, err = parsePortRange(hostPort)
		if err != nil {
			return nil, errors.New("invalid hostPort: " + hostPort)
		}
		if (endPort - startPort) != (endHostPort - startHostPort) {
			// Allow host port range iff containerPort is not a range.
			// In this case, use the host port range as the dynamic
			// host port range to allocate into.
			if endPort != startPort {
				return nil, fmt.Errorf("invalid ranges specified for container and host Ports: %s and %s", containerPort, hostPort)
			}
		}
	}

	count := endPort - startPort + 1
	ports := make([]PortMapping, 0, count)

	for i := 0; i < count; i++ {
		hPort := ""
		if hostPort != "" {
			hPort = strconv.Itoa(startHostPort + i)
			// Set hostPort to a range only if there is a single container port
			// and a dynamic host port.
			if count == 1 && startHostPort != endHostPort {
				hPort += "-" + strconv.Itoa(endHostPort)
			}
		}
		ports = append(ports, PortMapping{
			Port:    Port(strconv.Itoa(startPort+i) + "/" + proto),
			Binding: PortBinding{HostIP: ip, HostPort: hPort},
		})
	}
	return ports, nil
}
