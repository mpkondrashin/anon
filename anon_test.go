/*
Anon (c) 2023 by Mikhail Kondrashin (mkondrashin@gmail.com)
github.com/mpkondrashin/anon

anon_test.go

Test functions
*/
package anon

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"testing"
)

func TestHide(t *testing.T) {
	a := New(IP4, IP6, DNSName)
	testCases := []struct {
		input  string
		prefix string
	}{
		{"1.2.3.4", "IP:"},
		{"1:2:3:4:5:6:7:8", "IP6:"},
		{"www.com", "DNS:"},
		{"gopkg.in", "DNS:"},
	}
	for _, tCase := range testCases {
		actual := a.Hide(tCase.input)
		t.Log(actual)
		expected := tCase.prefix + a.hashAndEncode([]byte(tCase.input))
		if actual != expected {
			t.Errorf("For \"%s\", expected \"%s\", but got \"%s\"", tCase.input, expected, actual)
		}
	}
}

func TestOrder(t *testing.T) {
	input := "My email is michael@yahoo.com - please write me a letter"
	a := New(DNSName, Email).SetSalt([]byte{})
	output := a.Anonymize(input)
	t.Log(input)
	t.Log(output)
}

func ExampleAnonymizer_Anonymize() {
	a := New(IP4).AddDomains("local").SetSalt([]byte{})
	fmt.Println(a.Anonymize("My address is 192.168.10.25 or tiger.local"))
	// Output: My address is IP:EHbwEOPSp1Sh71NK9Das7K6u6N4 or DNS:Ebn_fbfAtZRMzYBMegpnLxUmNtQ
}
func ExampleAnonymizer_Hide_arbitrary() {
	a := New(IP4).SetSalt([]byte{})
	fmt.Println(a.Hide("My secret"))
	// Output: vBnoJvUuJJbzaC4V2tHUZH4Kyxg
}
func ExampleAnonymizer_Hide_ip() {
	a := New(IP4).SetSalt([]byte{})
	fmt.Println(a.Hide("10.10.1.1"))
	// Output: IP:qTQwwNaStHVodid1n8opcIH2xWo
}

func ExampleAnonymizer_AddConfidentialDomain() {
	a := New().AddDomains("in").SetSalt([]byte{})
	fmt.Println(a.Anonymize("gopkg.in"))
	fmt.Println(a.Anonymize("github.com"))
	// Output: DNS:yyOdkTCd0TtQXCbZxAyZHO-Lc48
	// github.com
}

func ExampleAnonymizer_AddConfidentialData() {
	anonymizer := New().SetSalt([]byte{})
	hide := regexp.MustCompile(`hide\(.+\)`)
	anonymizer.AddConfidentialData("hidden", hide, "")
	fmt.Print(anonymizer.Anonymize("Please hide(the following)!"))
	// Output: Please hidden:mGiY30dTiwzik-20Oi04XbZu7rA!
}

func ExampleAnonymizer_Writer() {
	anonymizer := New(IP4).SetSalt([]byte{})
	writer := anonymizer.Writer(os.Stdout)
	log.SetOutput(writer)
	log.SetFlags(0)
	log.Print("My address is 10.10.1.1")
	// Output: My address is IP:qTQwwNaStHVodid1n8opcIH2xWo
}

func ExampleHide() {
	SetSalt([]byte{})
	fmt.Println(Hide("192.168.10.25"))
	// Output: IP:EHbwEOPSp1Sh71NK9Das7K6u6N4
}

func ExampleAnonymize() {
	SetSalt([]byte{})
	fmt.Println(Anonymize("My address is 192.168.10.25"))
	// Output: My address is IP:EHbwEOPSp1Sh71NK9Das7K6u6N4
}

func ExampleWriter() {
	SetSalt([]byte{})
	writer := Writer(os.Stdout)
	log.SetOutput(writer)
	log.SetFlags(0)
	log.Print("My address is 10.10.1.1")
	// Output: My address is IP:qTQwwNaStHVodid1n8opcIH2xWo
}

/*
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
*/
/*
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
}*/

/*
func encodeReference2(data []byte) string {
	abc := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRTSUVWXYZ-_"
	encoding := base64.NewEncoding(abc)
	var sb strings.Builder
	encoder := base64.NewEncoder(encoding, &sb)
	_, err := encoder.Write(data)
	if err != nil {
		return err.Error()
	}
	return sb.String()
}
*/
