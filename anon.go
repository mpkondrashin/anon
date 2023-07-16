/*
Anon (c) 2023 by Mikhail Kondrashin (mkondrashin@gmail.com)
github.com/mpkondrashin/anon

anon.go

Go log anonymizer.
*/

// Package anon provides ability to avoid logging sensitive data by anonymizing it automatically using regexes.
// Anon supports IPv4, IPv6 and domain names and can be extended to other data types.
package anon

import (
	"crypto/sha1"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

var (
	ipv4NumBlock     = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	ipv4RegexPattern = ipv4NumBlock + `\.` + ipv4NumBlock + `\.` + ipv4NumBlock + `\.` + ipv4NumBlock
	ipv4RegEx        = regexp.MustCompile(ipv4RegexPattern)

	ipv6Blocks = []string{
		`([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}`,         // 1:2:3:4:5:6:7:8
		`([0-9a-fA-F]{1,4}:){1,7}:`,                        // 1::                              1:2:3:4:5:6:7::
		`([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}`,        // 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
		`([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}`, // 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
		`([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}`, // 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
		`([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}`, // 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
		`([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}`, // 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
		`[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})`,      // 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
		`:((:[0-9a-fA-F]{1,4}){1,7}|:)`,                    // ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
		`fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}`,    // fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
		`::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`, // ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
		`([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`,    // 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
	}
	ipv6RegexPattern = strings.Join(ipv6Blocks, "|")
	ipv6RegEx        = regexp.MustCompile(ipv6RegexPattern)

	domainNamePattern = `([a-zA-Z0-9][a-zA-Z0-9.-]{0,62}\.)+[a-zA-Z]{2,}`
	domainNameRegEx   = regexp.MustCompile(domainNamePattern)
)

type anonymizer struct {
	prefix string
	regex  *regexp.Regexp
}

var anonList = []anonymizer{
	{"Domain", domainNameRegEx},
	{"IP", ipv4RegEx},
	{"IP6", ipv6RegEx},
}

// Add provides ability to extend list of types of anonymized data
// as suun as one can provide appropriate regex
func Add(prefix string, regex *regexp.Regexp) {
	anonList = append(anonList, anonymizer{prefix, regex})
}

var (
	saltData []byte
)

func init() {
	seed := time.Now().UnixNano()
	saltData = make([]byte, 20)
	rand.New(rand.NewSource(seed)).Read(saltData)
}

// SetSalt - set fixed salt value instead generated randomly on each program run.
func SetSalt(salt []byte) {
	saltData = salt
}

// Hide - anonymize given value
func Hide(v any) string {
	s := fmt.Sprintf("%v", v)
	h := hashAndEncode([]byte(s))
	for _, each := range anonList {
		if each.regex.Match([]byte(s)) {
			return each.prefix + ":" + h
		}
	}
	return h
}

func hashAndEncode(data []byte) string {
	//s := fmt.Sprintf("%v", v)
	hasher := sha1.New()
	hasher.Write(data)
	return encode(hasher.Sum(saltData))
}

func anonymize(input string) (result string) {
	result = input
	for _, each := range anonList {
		result = each.regex.ReplaceAllStringFunc(result, func(s string) string {
			return each.prefix + ":" + hashAndEncode([]byte(s))
		})
	}
	return
}

// Writer - io.Writer comply struct that anonymezes all of the date written into it
// before passing to the next io.Writer.
type Writer struct {
	target io.Writer
}

// New - return new Writer to anonymize all of the data written to target io.Writer.
func New(target io.Writer) Writer {
	return Writer{
		target: target,
	}
}

// Write - anonymize data and write in to the target io.Writer
func (w Writer) Write(p []byte) (n int, err error) {
	s := anonymize(string(p))
	return w.target.Write([]byte(s))
}

func encode(data []byte) string {
	characters := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRTSUVWXYZ-_"
	length := (len(data)*4 + 2) / 3
	result := make([]byte, length)
	r := 0
	for i := 0; i < len(data); i++ {
		switch i % 3 {
		case 0:
			c := data[i]
			result[r] = characters[c&0x3F]
			r++
			if i == len(data)-1 {
				c := data[i] >> 6
				result[r] = characters[c&0x3F]
				r++
			}
		case 1:
			c := data[i]<<2 | data[i-1]>>6
			result[r] = characters[c&0x3F]
			r++
			if i == len(data)-1 {
				c := data[i] >> 4
				result[r] = characters[c&0x3F]
				r++
			}
		case 2:
			c := data[i]<<4 | data[i-1]>>4
			result[r] = characters[c&0x3F]
			r++
			c = data[i] >> 2
			result[r] = characters[c&0x3F]
			r++
		}
	}
	return string(result)
}
