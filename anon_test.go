/*
Anon (c) 2023 by Mikhail Kondrashin (mkondrashin@gmail.com)
github.com/mpkondrashin/anon

anon_test.go

Test functions
*/
package anon

import (
	"math/big"
	"math/rand"
	"strings"
	"testing"
)

func TestIPv4(t *testing.T) {
	tCase := "192.168.1.1"
	match := IPv4RegEx.Match([]byte(tCase))
	if !match {
		t.Errorf("Failed on %s", tCase)
	}
}

func TestIPv6(t *testing.T) {
	tCases := []string{
		"1:2:3:4:5:6:7:8",
		"1::", "1:2:3:4:5:6:7::",
		"1::8",
		"1:2:3:4:5:6::8", "1:2:3:4:5:6::8",
		"1::7:8", "1:2:3:4:5::7:8", "1:2:3:4:5::8",
		"1::6:7:8", "1:2:3:4::6:7:8", "1:2:3:4::8",
		"1::5:6:7:8", "1:2:3::5:6:7:8", "1:2:3::8",
		"1::4:5:6:7:8", "1:2::4:5:6:7:8", "1:2::8",
		"1::3:4:5:6:7:8", "1::3:4:5:6:7:8", "1::8",
		"::2:3:4:5:6:7:8", "::2:3:4:5:6:7:8", "::8", "::",
		"fe80::7:8%eth0", "fe80::7:8%1", //     (link-local IPv6 addresses with zone index)
		"::255.255.255.255", "::ffff:255.255.255.255", "::ffff:0:255.255.255.255", //  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
		"2001:db8:3:4::192.0.2.33", "64:ff9b::192.0.2.33", // (IPv4-Embedded IPv6 Address)
	}
	for _, ipv6 := range tCases {
		t.Run(ipv6, func(t *testing.T) {
			match := IPv6RegEx.Match([]byte(ipv6))
			if !match {
				t.Errorf("Failed on %s", ipv6)
			}
		})
	}
}

func TestDomainName(t *testing.T) {
	tCases := []struct {
		expected bool
		name     string
	}{
		{true, "www.com"},
		{true, "www.site.info"},
		{false, "name"},
		{true, "0www.com"},
		{true, "abc012345678901234567890123456789012345678901234567890123456789.com"},
		{true, "Dial SMS (www.google.com)"},
	}
	for _, tCase := range tCases {
		t.Run(tCase.name, func(t *testing.T) {
			match := DomainNameRegEx.Match([]byte(tCase.name))
			if match != tCase.expected {
				t.Errorf("%s: expected %v but got %v", tCase.name, tCase.expected, match)
			}
		})
	}
}

func TestTo64(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0b00000001}, "10"},
		{[]byte{0b00000010}, "20"},
		{[]byte{0b01000001}, "11"},
		{[]byte{0b01000001, 0b010000}, "111"},
		{[]byte{0b10000001, 0b110000}, "123"},
		{[]byte{0b10000001, 0b00110000, 0b00010000}, "1234"},
		{[]byte{0b01000001, 0b00010000, 0b00000100}, "1111"},
		{[]byte{0b01000001, 0b00010000, 0b00000100, 0b01000001}, "111111"},
	}

	for _, tCase := range testCases {
		t.Run(tCase.expected, func(t *testing.T) {
			actual := encode(tCase.input)
			if actual != tCase.expected {
				t.Errorf("%v: %s != %s", tCase.input, actual, tCase.expected)
			}
			expected := encodeReference(tCase.input)
			if actual != expected {
				t.Errorf("Reference %v: %s != %s", tCase.input, actual, expected)
			}
		})
	}
	t.Run("random", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			length := rand.Intn(100)
			input := make([]byte, length)
			for j := 0; j < length; j++ {
				input[j] = byte(rand.Int())
			}
			actual := encode(input)
			expected := encodeReference(input)
			if actual != expected {
				t.Errorf("Reference %v: %s != %s", input, actual, expected)
			}
		}
	})
}

func encodeReference(data []byte) string {
	// Reverse data
	d := data[:]
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
	var sb strings.Builder
	v := new(big.Int).SetBytes(d)
	characters := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRTSUVWXYZ-_"
	length := big.NewInt(int64(len(characters)))
	m := new(big.Int)
	for i := 0; i < (len(data)*4+2)/3; i++ {
		v, m = v.DivMod(v, length, m)
		c := characters[m.Uint64()]
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

func TestHide(t *testing.T) {
	testCases := []struct {
		input  string
		prefix string
	}{
		{"1.2.3.4", "IP:"},
		{"1:2:3:4:5:6:7:8", "IP6:"},
		{"www.com", "Domain:"},
	}
	for _, tCase := range testCases {
		actual := Hide(tCase.input)
		t.Log(actual)
		expected := tCase.prefix + hashAndEncode([]byte(tCase.input))
		if actual != expected {
			t.Errorf("For \"%s\", expected \"%s\", but got \"%s\"", tCase.input, expected, actual)
		}
	}
}
