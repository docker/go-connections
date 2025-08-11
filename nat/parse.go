package nat

import (
	"errors"
	"strconv"
	"strings"
)

// ParsePortRange parses and validates the specified string as a port-range (8000-9000)
func ParsePortRange(ports string) (uint64, uint64, error) {
	if ports == "" {
		return 0, 0, errors.New("empty string specified for ports")
	}
	if !strings.Contains(ports, "-") {
		start, err := strconv.ParseUint(ports, 10, 16)
		end := start
		return start, end, err
	}

	parts := strings.Split(ports, "-")
	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, err
	}
	end, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, 0, err
	}
	if end < start {
		return 0, 0, errors.New("invalid range specified for port: " + ports)
	}
	return start, end, nil
}

// parsePortNumber parses rawPort into an int, unwrapping strconv errors
// and returning a single "out of range" error for any value outside 0–65535.
func parsePortNumber(rawPort string) (int, error) {
	if rawPort == "" {
		return 0, errors.New("value is empty")
	}
	port, err := strconv.ParseInt(rawPort, 10, 0)
	if err != nil {
		var numErr *strconv.NumError
		if errors.As(err, &numErr) {
			err = numErr.Err
		}
		return 0, err
	}
	if port < 0 || port > 65535 {
		return 0, errors.New("value out of range (0–65535)")
	}

	return int(port), nil
}
