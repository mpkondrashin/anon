/*
Anon (c) 2023 by Mikhail Kondrashin (mkondrashin@gmail.com)
github.com/mpkondrashin/anon

anon.go

Go log anonymizer.
*/

// Package anon allows to avoid logging sensitive data by anonymizing it automatically or manually.
// Anon supports IPv4, IPv6 and other types of data to anonymyze them them automatically.
// List of sensitive data types can be extended if nessesary regex can be provided.
// Each recognized piece of confidentional data will be changed to something like ```go7YgcKQDilELf_iQr3HIXGHE-d```.
// This value will be the same for all same values for this program run.
// On the next run, this string of characters will be different, but for same values within this run, it will still be the same.
// This property of obfuscated data gives ability to compare anonymized values.
package anon

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"sort"
	"time"

	"golang.org/x/exp/constraints"
)

// DataType - confidential data type

//go:generate enum -package=anon -type=DataType -noprefix -values=Email,CreditCard,UUID3,UUID4,UUID5,UUID,Latitude,Longitude,IP4,IP6,DNSName,URL,SSN,IMEI,IMSI,E164
//go:generate go fmt enum_datatype.go

// Anonymizer - struct to anonymize text.
type Anonymizer struct {
	salt                 []byte
	confidentialDataList []confidentialData
}

// New - return new Anonymizer with random salt that will obfuscate automatically given list of types.
func New(types ...DataType) *Anonymizer {
	a := Anonymizer{
		salt: randomSalt(),
	}
	sTypes := types[:]
	sortSlice(sTypes)
	for _, t := range sTypes {
		a.confidentialDataList = append(a.confidentialDataList, confidentailData[t])
	}
	return &a
}

// SetSalt - set salt value instead of generated randomly.
func (a *Anonymizer) SetSalt(salt []byte) *Anonymizer {
	a.salt = salt
	return a
}

// AddConfidentialData provides ability to extend list of types of anonymized data.
func (a *Anonymizer) AddConfidentialData(prefix string, regex *regexp.Regexp, example string) *Anonymizer {
	a.confidentialDataList = append(a.confidentialDataList, confidentialData{
		prefix: prefix,
		regex:  regex,
	})
	return a
}

// AddDomains provides ability to anonymize DNS names for given top level domains.
func (a *Anonymizer) AddDomains(tlds ...string) *Anonymizer {
	for _, tld := range tlds {
		a.AddConfidentialData("DNS", regexp.MustCompile(PatternDNSSubDomain+regexp.QuoteMeta(tld)), "")
	}
	return a
}

// Hide - anonymize given value. Prefix will be added automatically, if type will be detected.
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

// Anonymize - anonymyze confidential data found in string.
func (a *Anonymizer) Anonymize(input string) (result string) {
	result = input
	for _, each := range a.confidentialDataList {
		result = each.regex.ReplaceAllStringFunc(result, func(s string) string {
			return each.prefix + ":" + a.hashAndEncode([]byte(s))
		})
	}
	return
}

// writer - io.writer comply struct that anonymezes all of the date written into it
// before passing to the next io.writer.
type writer struct {
	anonymyzer *Anonymizer
	target     io.Writer
}

// Writer - return new io.Writer to anonymize data before writing to the target io.Writer.
func (a *Anonymizer) Writer(target io.Writer) writer {
	return writer{
		anonymyzer: a,
		target:     target,
	}
}

// Write - anonymize data and write in to the target io.Writer
func (w writer) Write(p []byte) (n int, err error) {
	s := w.anonymyzer.Anonymize(string(p))
	return w.target.Write([]byte(s))
}

func (a *Anonymizer) hashAndEncode(data []byte) string {
	hasher := sha1.New()
	hasher.Write(a.salt)
	hasher.Write(data)
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

// defaultAnonymizer - anonymizer used for package global functions.
var defaultAnonymizer = New(Email, CreditCard, IP4, IP6, URL)

// SetSalt - set salt value instead of random default value
func SetSalt(salt []byte) {
	defaultAnonymizer.SetSalt(salt)
}

// Hide - anonymize given value using default anonymizer.
func Hide(v any) string {
	return defaultAnonymizer.Hide(v)
}

// Anonymize - anonymize confidential data found in string using default anonymizer.
func Anonymize(input string) string {
	return defaultAnonymizer.Anonymize(input)
}

// Writer - return new io.Writer to anonymize all of the data before writing it to target
// using default anonymizer.
func Writer(target io.Writer) writer {
	return defaultAnonymizer.Writer(target)
}

func sortSlice[T constraints.Ordered](s []T) {
	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
}

func randomSalt() []byte {
	seed := time.Now().UnixNano()
	salt := make([]byte, 20)
	rand.New(rand.NewSource(seed)).Read(salt)
	return salt
}

/*
	func _encode(data []byte) string {
		abc := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRTSUVWXYZ-_"
		length := (len(data)*4 + 2) / 3
		result := make([]byte, length)
		r := 0
		for i := 0; i < len(data); i++ {
			switch i % 3 {
			case 0:
				c := data[i]
				result[r] = abc[c&0x3F]
				r++
				if i == len(data)-1 {
					c := data[i] >> 6
					result[r] = abc[c&0x3F]
					r++
				}
			case 1:
				c := data[i]<<2 | data[i-1]>>6
				result[r] = abc[c&0x3F]
				r++
				if i == len(data)-1 {
					c := data[i] >> 4
					result[r] = abc[c&0x3F]
					r++
				}
			case 2:
				c := data[i]<<4 | data[i-1]>>4
				result[r] = abc[c&0x3F]
				r++
				c = data[i] >> 2
				result[r] = abc[c&0x3F]
				r++
			}
		}
		return string(result)
	}
*/
