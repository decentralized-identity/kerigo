package event

type SealOption func(*Seal) error

// Seal is used to anchor particular data to an event
// There are multiple types of seals, each with
// a different combination of data points.
type Seal struct {
	Root      string `json:"root,omitempty"`
	Prefix    string `json:"pre,omitempty"`
	Sequence  string `json:"sn,omitempty"`
	EventType string `json:"ilk,omitempty"`
	Digest    string `json:"dig,omitempty"`
}
