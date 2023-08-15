package anon

import (
	"regexp"
	"strings"
)

// modified version from https://github.com/asaskevich/govalidator

// Regular expressions for various data types.
const (
	PatternEmail        string = "(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?"
	PatternCreditCard   string = "(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|(222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11}|6[27][0-9]{14})"
	PatternUUID3        string = "[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}"
	PatternUUID4        string = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
	PatternUUID5        string = "[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
	PatternUUID         string = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	PatternLatitude     string = "[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)"
	PatternLongitude    string = "[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)"
	PatternLocation     string = PatternLatitude + "|" + PatternLongitude
	PatternIPv4         string = `(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`
	___bad___PatternIP  string = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	PatternDNSName      string = `([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})+[\._]?` // Changed * to + not to detect "yahoo" as valid DNS name, but only "yahoo.com"
	PatternDNSSubDomain string = `([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}\.)+`
	URLSchema           string = `((ftp|tcp|udp|wss?|https?):\/\/)`
	URLUsername         string = `(\S+(:\S*)?@)`
	URLPath             string = `((\/|\?|#)[^\s]*)`
	URLPort             string = `(:(\d{1,5}))`
	URLIP               string = `([1-9]\d?|1\d\d|2[01]\d|22[0-3]|24\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-5]))`
	URLSubdomain        string = `((www\.)|([a-zA-Z0-9]+([-_\.]?[a-zA-Z0-9])*[a-zA-Z0-9]\.[a-zA-Z0-9]+))`
	PatternURL                 = URLSchema + URLUsername + `?` + `((` + URLIP + `|(\[` + ___bad___PatternIP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + URLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + URLPort + `?` + URLPath + `?`
	PatternSSN          string = `\d{3}[- ]?\d{2}[- ]?\d{4}`
	PatternIMEI         string = "[0-9a-f]{14}$|^\\d{15}$|^\\d{18}"
	PatternIMSI         string = "\\d{14,15}"
	PatternE164         string = `\+?[1-9]\d{1,14}`
)

var (
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
)

var (
	rxEmail      = regexp.MustCompile(PatternEmail)
	rxCreditCard = regexp.MustCompile(PatternCreditCard)
	rxUUID3      = regexp.MustCompile(PatternUUID3)
	rxUUID4      = regexp.MustCompile(PatternUUID4)
	rxUUID5      = regexp.MustCompile(PatternUUID5)
	rxUUID       = regexp.MustCompile(PatternUUID)
	rxLatitude   = regexp.MustCompile(PatternLatitude)
	rxLongitude  = regexp.MustCompile(PatternLongitude)
	rxIPv6       = regexp.MustCompile(ipv6RegexPattern) //PatternIP)
	rxIPv4       = regexp.MustCompile(URLIP)
	rxDNSName    = regexp.MustCompile(PatternDNSName)
	rxURL        = regexp.MustCompile(PatternURL)
	rxSSN        = regexp.MustCompile(PatternSSN)
	rxIMEI       = regexp.MustCompile(PatternIMEI)
	rxIMSI       = regexp.MustCompile(PatternIMSI)
	rxE164       = regexp.MustCompile(PatternE164)
)

type confidentialData struct {
	prefix string
	regex  *regexp.Regexp
}

var confidentailData = map[DataType]confidentialData{
	Email:      {"Email", rxEmail},
	CreditCard: {"CreditCard", rxCreditCard},
	UUID3:      {"UUID3", rxUUID3},
	UUID4:      {"UUID4", rxUUID4},
	UUID5:      {"UUID5", rxUUID5},
	UUID:       {"UUID", rxUUID},
	Latitude:   {"Latidude", rxLatitude},
	Longitude:  {"Longitude", rxLongitude},
	IP4:        {"IP", rxIPv4},
	IP6:        {"IP6", rxIPv6},
	DNSName:    {"DNS", rxDNSName},
	URL:        {"URL", rxURL},
	SSN:        {"SSN", rxSSN},
	IMEI:       {"IMEI", rxIMEI},
	IMSI:       {"IMSI", rxIMSI},
	E164:       {"E162", rxE164},
}
