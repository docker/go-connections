package nat

import "testing"

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		doc      string
		input    string
		expBegin uint64
		expEnd   uint64
		expErr   string
	}{
		{
			doc:    "empty value",
			expErr: `empty string specified for ports`,
		},
		{
			doc:      "single port",
			input:    "1234",
			expBegin: 1234,
			expEnd:   1234,
		},
		{
			doc:      "single port range",
			input:    "1234-1234",
			expBegin: 1234,
			expEnd:   1234,
		},
		{
			doc:      "two port range",
			input:    "1234-1235",
			expBegin: 1234,
			expEnd:   1235,
		},
		{
			doc:      "large range",
			input:    "8000-9000",
			expBegin: 8000,
			expEnd:   9000,
		},
		{
			doc:   "zero port",
			input: "0",
		},
		{
			doc:   "zero range",
			input: "0-0",
		},
		// invalid cases
		{
			doc:    "non-numeric port",
			input:  "asdf",
			expErr: `invalid start port 'asdf': invalid syntax`,
		},
		{
			doc:    "reversed range",
			input:  "9000-8000",
			expErr: `invalid port range: 9000-8000`,
		},
		{
			doc:    "range missing end",
			input:  "8000-",
			expErr: `invalid end port '': value is empty`,
		},
		{
			doc:    "range missing start",
			input:  "-9000",
			expErr: `invalid start port '': value is empty`,
		},
		{
			doc:    "invalid range end",
			input:  "8000-a",
			expErr: `invalid end port 'a': invalid syntax`,
		},
		{
			doc:    "invalid range end port",
			input:  "8000-9000a",
			expErr: `invalid end port '9000a': invalid syntax`,
		},
		{
			doc:    "range range start",
			input:  "a-9000",
			expErr: `invalid start port 'a': invalid syntax`,
		},
		{
			doc:    "range range start port",
			input:  "8000a-9000",
			expErr: `invalid start port '8000a': invalid syntax`,
		},
		{
			doc:    "range with trailing hyphen",
			input:  "-8000-",
			expErr: `invalid start port '': value is empty`,
		},
		{
			doc:    "range without ports",
			input:  "-",
			expErr: `invalid start port '': value is empty`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.doc, func(t *testing.T) {
			begin, end, err := ParsePortRange(tc.input)
			if tc.expErr == "" {
				if err != nil {
					t.Error(err)
				}
			} else {
				if err == nil || err.Error() != tc.expErr {
					t.Errorf("expected error '%s', got '%v'", tc.expErr, err)
				}
			}
			if begin != tc.expBegin {
				t.Errorf("expected begin %d, got %d", tc.expBegin, begin)
			}
			if end != tc.expEnd {
				t.Errorf("expected end %d, got %d", tc.expEnd, end)
			}
		})
	}
}

func TestParsePortNumber(t *testing.T) {
	tests := []struct {
		doc    string
		input  string
		exp    int
		expErr string
	}{
		{
			doc:    "empty string",
			input:  "",
			expErr: "value is empty",
		},
		{
			doc:    "whitespace only",
			input:  "   ",
			expErr: "invalid syntax",
		},
		{
			doc:   "single valid port",
			input: "1234",
			exp:   1234,
		},
		{
			doc:   "zero port",
			input: "0",
			exp:   0,
		},
		{
			doc:   "max valid port",
			input: "65535",
			exp:   65535,
		},
		{
			doc:    "leading/trailing spaces",
			input:  "  42  ",
			expErr: "invalid syntax",
		},
		{
			doc:    "negative port",
			input:  "-1",
			expErr: "value out of range (0–65535)",
		},
		{
			doc:    "too large port",
			input:  "70000",
			expErr: "value out of range (0–65535)",
		},
		{
			doc:    "non-numeric",
			input:  "foo",
			expErr: "invalid syntax",
		},
		{
			doc:    "trailing garbage",
			input:  "1234abc",
			expErr: "invalid syntax",
		},
	}

	for _, tc := range tests {
		t.Run(tc.doc, func(t *testing.T) {
			got, err := parsePortNumber(tc.input)

			if tc.expErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.exp {
					t.Errorf("expected %d, got %d", tc.exp, got)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.expErr)
				}
				if err.Error() != tc.expErr {
					t.Errorf("expected error %q, got %q", tc.expErr, err.Error())
				}
			}
		})
	}
}
