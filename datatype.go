package anon

import (
	"errors"
	"fmt"
)

// DataType - confidential data type
type DataType uint64

const (
	Email DataType = 1 << iota
	CreditCard
	UUID3
	UUID4
	UUID5
	UUID
	Latitude
	Longitude
	IP4
	IP6
	DNSName
	URL
	SSN
	IMEI
	IMSI
	E164
)

// String - return string representation for data type
func (d DataType) String() string {
	s, ok := map[DataType]string{
		Email:      "Email",
		CreditCard: "CreditCard",
		UUID3:      "UUID3",
		UUID4:      "UUID4",
		UUID5:      "UUID5",
		UUID:       "UUID",
		Latitude:   "Latitude",
		Longitude:  "Longitude",
		IP4:        "IP4",
		IP6:        "IP6",
		DNSName:    "DNSName",
		URL:        "URL",
		SSN:        "SSN",
		IMEI:       "IMEI",
		IMSI:       "IMSI",
		E164:       "E164",
	}[d]
	if !ok {
		return "unknonwn"
	}
	return s
}

// ErrDataTypeUnknown - will be returned when parsing data type from string
// for unrecognized type.
var ErrDataTypeUnknown = errors.New("unknown data type")

// String - return data type for string or ErrUnknownDataType if type is unknown.
func DataTypeFromString(s string) (DataType, error) {
	d, ok := map[string]DataType{
		"Email":      Email,
		"CreditCard": CreditCard,
		"UUID3":      UUID3,
		"UUID4":      UUID4,
		"UUID5":      UUID5,
		"UUID":       UUID,
		"Latitude":   Latitude,
		"Longitude":  Longitude,
		"IP4":        IP4,
		"IP6":        IP6,
		"DNSName":    DNSName,
		"URL":        URL,
		"SSN":        SSN,
		"IMEI":       IMEI,
		"IMSI":       IMSI,
		"E164":       E164,
	}[s]
	if !ok {
		return 0, fmt.Errorf("%s: %w", s, ErrDataTypeUnknown)
	}
	return d, nil
}

// Implements the Unmarshaler interface of the yaml pkg for DataType.
func (d *DataType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, err := DataTypeFromString(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}
