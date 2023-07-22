/*
Anon (c) 2023 by Mikhail Kondrashin (mkondrashin@gmail.com)
github.com/mpkondrashin/anon

anon.go

Go log anonymizer.
*/

// Package anon provides ability to avoid logging sensitive data by anonymizing it automatically.
// Anon supports IPv4, IPv6 and domain names and can be extended to other data types.
// Each recognized piece of confidentional data will be changed to something like ```zjOZKfxm-4PpBYwD0r9iZQlguy8PEmvjBKwsHDtEuvGP6_EcyKmEC2```.
// This value will be the same for all same values for this program run.
// On the next run, this string of characters will be different, but for same values it will still be the same.
// This property of obfuscated data gives ability to compare anonymized values.
package anon

import (
	"crypto/sha1"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"time"
)

// Anonymizer - struct to anonymize text.
type Anonymizer struct {
	salt                 []byte
	confidentialDataList []confidentialData
}

// New - return new Anonymizer with random salt.
func New(types DataType) *Anonymizer {
	a := Anonymizer{
		salt: randomSalt(),
	}
	for i := 0; i < 64; i++ {
		t := DataType(1 << i)
		if t&types == 0 {
			continue
		}
		a.confidentialDataList = append(a.confidentialDataList, confidentailData[t])
	}
	return &a
}

// SetSalt - set salt value instead generated randomly.
func (a *Anonymizer) SetSalt(salt []byte) *Anonymizer {
	a.salt = salt
	return a
}

// AddConfidentialData provides ability to extend list of types of anonymized data
// as soon as appropriate regex can be provided.
func (a *Anonymizer) AddConfidentialData(prefix string, regex *regexp.Regexp, example string) *Anonymizer {
	a.confidentialDataList = append(a.confidentialDataList, confidentialData{
		prefix:  prefix,
		regex:   regex,
		example: example,
	})
	return a
}

// AddConfidentialDomain provides ability to anonymize DNS names for given top level domain.
func (a *Anonymizer) AddConfidentialDomain(tld string) *Anonymizer {
	a.confidentialDataList = append(a.confidentialDataList, confidentialData{
		prefix: "DNS",
		regex:  regexp.MustCompile(PatternDNSSubDomain + regexp.QuoteMeta(tld)),
	})
	return a
}

// Hide - anonymize given value
func (a *Anonymizer) Hide(v any) string {
	s := fmt.Sprintf("%v", v)
	h := a.hashAndEncode([]byte(s))
	for _, each := range a.confidentialDataList {
		if each.regex.Match([]byte(s)) {
			return each.prefix + ":" + h
		}
	}
	return h
}

func (a *Anonymizer) hashAndEncode(data []byte) string {
	hasher := sha1.New()
	hasher.Write(data)
	return encode(hasher.Sum(a.salt))
}

// Anonymize - anonymyzer confidential data found in string.
func (a *Anonymizer) Anonymize(input string) (result string) {
	result = input
	for _, each := range a.confidentialDataList {
		result = each.regex.ReplaceAllStringFunc(result, func(s string) string {
			return each.prefix + ":" + a.hashAndEncode([]byte(s))
		})
	}
	return
}

type confidentialData struct {
	prefix  string
	regex   *regexp.Regexp
	example string
}

func randomSalt() []byte {
	seed := time.Now().UnixNano()
	salt := make([]byte, 20)
	rand.New(rand.NewSource(seed)).Read(salt)
	return salt
}

// Writer - io.Writer comply struct that anonymezes all of the date written into it
// before passing to the next io.Writer.
type Writer struct {
	anonymyzer *Anonymizer
	target     io.Writer
}

// Writer - return new io.Writer to anonymize data before writing to the target io.Writer.
func (a *Anonymizer) Writer(target io.Writer) Writer {
	return Writer{
		anonymyzer: a,
		target:     target,
	}
}

// Write - anonymize data and write in to the target io.Writer
func (w Writer) Write(p []byte) (n int, err error) {
	s := w.anonymyzer.Anonymize(string(p))
	return w.target.Write([]byte(s))
}

func encode(data []byte) string {
	//fmt.Println(len(data), data)
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
	//fmt.Println("RESULT", len(result))
	return string(result)
}

// defaultAnonymizer - anonymizer used for package global functions.
var defaultAnonymizer = New(Email | CreditCard | IP4 | IP6 | URL)

// Hide - anonymize given value using default anonymizer.
func Hide(v any) string {
	return defaultAnonymizer.Hide(v)
}

// Anonymizer - anonymize confidential data found in string using default anonymizer.
func Anonymize(input string) string {
	return defaultAnonymizer.Anonymize(input)
}

// NewWriter - return new Writer to anonymize all of the data written to target io.Writer
// using default anonymizer.
func NewWriter(target io.Writer) Writer {
	return defaultAnonymizer.Writer(target)
}

/*
var (

	ipv4NumBlock     = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	ipv4RegexPattern = ipv4NumBlock + `\.` + ipv4NumBlock + `\.` + ipv4NumBlock + `\.` + ipv4NumBlock
	ipv4RegEx        = regexp.MustCompile(ipv4RegexPattern)
	ConfDataIPv4     = confidentialData{"IP", ipv4RegEx, "192.168.100.1"}

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
	ConfDataIPv6     = confidentialData{"IP6", domainNameRegEx, "1:2:3:4:5:6:7:8"}

	domainNamePattern = `([a-zA-Z0-9][a-zA-Z0-9.-]{0,62}\.)+[a-zA-Z]{2,}`
	domainNameRegEx   = regexp.MustCompile(domainNamePattern)
	ConfDataDomain    = confidentialData{"Domain", domainNameRegEx, "www.yahoo.com"}

)
*/
