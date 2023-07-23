// Code generated by enum (github.com/mpkondrashin/enum). DO NOT EDIT

package anon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type DataType int

const (
	Email      DataType = iota
	CreditCard DataType = iota
	UUID3      DataType = iota
	UUID4      DataType = iota
	UUID5      DataType = iota
	UUID       DataType = iota
	Latitude   DataType = iota
	Longitude  DataType = iota
	IP4        DataType = iota
	IP6        DataType = iota
	DNSName    DataType = iota
	URL        DataType = iota
	SSN        DataType = iota
	IMEI       DataType = iota
	IMSI       DataType = iota
	E164       DataType = iota
)

// String - return string representation for DataType value
func (v DataType) String() string {
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
	}[v]
	if ok {
		return s
	}
	return "DataType(" + strconv.FormatInt(int64(v), 10) + ")"
}

// ErrUnknownDataType - will be returned wrapped when parsing string
// containing unrecognized value.
var ErrUnknownDataType = errors.New("unknown DataType")

var mapDataTypeFromString = map[string]DataType{
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
}

// UnmarshalJSON implements the Unmarshaler interface of the json package for DataType.
func (s *DataType) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	result, ok := mapDataTypeFromString[v]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownDataType, v)
	}
	*s = result
	return nil
}

// UnmarshalYAML implements the Unmarshaler interface of the yaml.v3 package for DataType.
func (s *DataType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	result, ok := mapDataTypeFromString[v]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownDataType, v)
	}
	*s = result
	return nil
}