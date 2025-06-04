// Package models contains shared utility types.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
	"github.com/lib/pq"
)

// CustomTime is a helper type for parsing non-standard timestamp formats found in CVE data sources, particularly those that don't conform to time.RFC3339.
type CustomTime struct {
	time.Time
}

// UnmarshalJSON parses a timestamp string from CVE JSON data, handling cases where the format does not strictly follow RFC3339.
func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	s = s[1 : len(s)-1]
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil {
		return err
	}
	ct.Time = t
	return nil
}

// StringArray is a custom type for storing []string as PostgreSQL text[].
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	// return json.Marshal(a)
	return pq.Array([]string(a)).Value()
}

func (a *StringArray) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &a)
	}
	return json.Unmarshal(b, &a)
}
