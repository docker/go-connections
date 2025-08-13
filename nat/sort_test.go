package nat

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func TestSortUniquePorts(t *testing.T) {
	ports := []Port{
		MustParsePort("6379/tcp"),
		MustParsePort("22/tcp"),
	}

	Sort(ports, func(ip, jp Port) bool {
		return ip.Int() < jp.Int() || (ip.Int() == jp.Int() && ip.Proto() == "tcp")
	})

	first := ports[0]
	if first.String() != "22/tcp" {
		t.Log(first)
		t.Fail()
	}
}

func TestSortSamePortWithDifferentProto(t *testing.T) {
	ports := []Port{
		MustParsePort("8888/tcp"),
		MustParsePort("8888/udp"),
		MustParsePort("6379/tcp"),
		MustParsePort("6379/udp"),
	}

	Sort(ports, func(ip, jp Port) bool {
		return ip.Int() < jp.Int() || (ip.Int() == jp.Int() && ip.Proto() == "tcp")
	})

	first := ports[0]
	if first.String() != "6379/tcp" {
		t.Fail()
	}
}

func TestSortPortMap(t *testing.T) {
	ports := []Port{
		MustParsePort("22/tcp"),
		MustParsePort("22/udp"),
		MustParsePort("8000/tcp"),
		MustParsePort("8443/tcp"),
		MustParsePort("6379/tcp"),
		MustParsePort("9999/tcp"),
	}

	portMap := map[Port][]PortBinding{
		MustParsePort("22/tcp"):   {{}},
		MustParsePort("8000/tcp"): {{}},
		MustParsePort("8443/tcp"): {},
		MustParsePort("6379/tcp"): {{}, {HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "32749"}},
		MustParsePort("9999/tcp"): {{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "40000"}},
	}

	SortPortMap(ports, portMap)
	if !reflect.DeepEqual(ports, []Port{
		MustParsePort("9999/tcp"),
		MustParsePort("6379/tcp"),
		MustParsePort("8443/tcp"),
		MustParsePort("8000/tcp"),
		MustParsePort("22/tcp"),
		MustParsePort("22/udp"),
	}) {
		t.Errorf("failed to prioritize port with explicit mappings, got %v", ports)
	}
	if pm := portMap[MustParsePort("6379/tcp")]; !reflect.DeepEqual(pm, []PortBinding{
		{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "32749"},
		{},
	}) {
		t.Errorf("failed to prioritize bindings with explicit mappings, got %v", pm)
	}
}

func BenchmarkSortPortMap(b *testing.B) {
	const n = 100
	ports := make([]Port, 0, n*2)
	portMap := make(map[Port][]PortBinding, n*2)

	for i := 0; i < n; i++ {
		portNum := 30000 + (i % 50) // force duplicate port numbers
		tcp := MustParsePort(fmt.Sprintf("%d/tcp", portNum))
		udp := MustParsePort(fmt.Sprintf("%d/udp", portNum))

		ports = append(ports, tcp, udp)

		portMap[tcp] = []PortBinding{
			{HostIP: netip.MustParseAddr("127.0.0.2"), HostPort: fmt.Sprint(40000 + i)},
			{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: fmt.Sprint(40000 + i)},
		}
		portMap[udp] = []PortBinding{
			{HostIP: netip.MustParseAddr("127.0.0.2"), HostPort: fmt.Sprint(40000 + i)},
			{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: fmt.Sprint(40000 + i)},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		portsCopy := make([]Port, len(ports))
		copy(portsCopy, ports)

		bindingsCopy := make(map[Port][]PortBinding, len(portMap))
		for k, v := range portMap {
			bindingsCopy[k] = append([]PortBinding(nil), v...)
		}

		SortPortMap(portsCopy, bindingsCopy)
	}
}
