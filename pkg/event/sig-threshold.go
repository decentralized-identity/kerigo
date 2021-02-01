package event

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/pkg/errors"
)

type SigThreshold struct {
	conditions [][]*big.Rat
}

// MarshalJSON is used to correctly output the JSON since this field can
// contain a single int, a list, or a list of lists
func (s *SigThreshold) MarshalJSON() ([]byte, error) {
	switch len(s.conditions) {
	case 0:
		return json.Marshal("0")
	case 1:
		if len(s.conditions[0]) == 1 {
			return json.Marshal(s.conditions[0][0])
		}
		return json.Marshal(s.conditions[0])
	}

	return json.Marshal(s.conditions)
}

func (s *SigThreshold) UnmarshalJSON(in []byte) error {
	// check the smiplest first - that the input is a simple string
	if string(in[:1]) == `"` {
		parsed := ""
		err := json.Unmarshal(in, &parsed)
		if err != nil {
			return nil
		}

		tholdint, err := strconv.Atoi(parsed)
		if err != nil {
			return err
		}

		s.conditions = [][]*big.Rat{{big.NewRat(int64(tholdint), 1)}}
		return nil
	}

	// it's either a list, or list of lists
	tholds := []interface{}{}

	err := json.Unmarshal(in, &tholds)
	if err != nil {
		return err
	}

	if len(tholds) == 0 {
		s.conditions = [][]*big.Rat{}
	} else {
		// if the first item is a string, we will treat this as a weighted thresholed
		if _, ok := tholds[0].(string); ok {
			conditions := []string{}
			for _, t := range tholds {
				if ts, ok := t.(string); ok {
					conditions = append(conditions, ts)
				}
			}

			converted, err := parseConditions(conditions)
			if err != nil {
				return err
			}

			s.conditions = append(s.conditions, converted)
		}

		// if the first item is a slice, we will treat this as a multi-weighted
		if _, ok := tholds[0].([]interface{}); ok {
			for _, t := range tholds {
				if ti, ok := t.([]interface{}); ok {
					conditions := []string{}
					for _, iface := range ti {
						if ts, ok := iface.(string); ok {
							conditions = append(conditions, ts)
						}
					}

					converted, err := parseConditions(conditions)
					if err != nil {
						return err
					}

					s.conditions = append(s.conditions, converted)
				}
			}
		}
	}

	return nil
}

func parseConditions(conditions []string) ([]*big.Rat, error) {
	converted := []*big.Rat{}
	for _, c := range conditions {
		thold := new(big.Rat)

		_, err := fmt.Sscan(c, thold)
		if err != nil {
			return nil, fmt.Errorf("unable to parse condition %s: %s", c, err)
		}

		if thold.Sign() == -1 {
			return nil, errors.New("thresholds must be >= 0")
		}

		converted = append(converted, thold)
	}

	return converted, nil
}

// Satisfied takes the provided signature derivations and checkes each weighted
// threshold
func (s *SigThreshold) Satisfied(sigs []derivation.Derivation) bool {
	if !s.Weighted() {
		required := 0
		if len(s.conditions) == 1 && len(s.conditions[0]) == 1 {
			required = int(s.conditions[0][0].Num().Int64())
		}
		return len(sigs) >= required
	}

	for _, c := range s.conditions {
		weight := big.NewRat(0, 1)
		for _, s := range sigs {
			// if our index is outside of the weighted list it doesn't count
			if int(s.KeyIndex) >= len(c) {
				continue
			}

			weight.Add(weight, c[int(s.KeyIndex)])
		}

		// if we failed to meet this weight, return false
		if weight.Cmp(big.NewRat(1, 1)) == -1 {
			return false
		}
	}

	return true
}

// returns true if this is a weighted threshold - i.e. there
// is one or more lists of weights
func (s *SigThreshold) Weighted() bool {
	if len(s.conditions) < 1 || (len(s.conditions) == 1 && len(s.conditions[0]) == 1) {
		return false
	}

	return true
}

// New returns a signing threshold requiring 'threshold' signatures
func NewSigThreshold(threshold int64) (*SigThreshold, error) {
	if threshold < 0 {
		return nil, errors.New("threshold must be >= 0")
	}

	return &SigThreshold{[][]*big.Rat{{big.NewRat(threshold, 1)}}}, nil
}

// NewWeighted creates a new sighing threshold with a weighted multisig
func NewWeighted(conditions ...string) (*SigThreshold, error) {
	sum := new(big.Rat)

	converted, err := parseConditions(conditions)
	if err != nil {
		return nil, err
	}

	for _, c := range converted {
		sum.Add(sum, c)
	}

	if sum.Cmp(big.NewRat(1, 1)) == -1 {
		return nil, errors.New("threshold not satifiable: sum of weights must be greather than 1")
	}

	return &SigThreshold{conditions: [][]*big.Rat{converted}}, nil
}

// NewMultiWeighted creates a new signing threshold with multiple
// conditions
func NewMultiWeighted(conditions ...[]string) (*SigThreshold, error) {
	thresholds := [][]*big.Rat{}

	for _, c := range conditions {
		tot := new(big.Rat)
		converted, err := parseConditions(c)
		if err != nil {
			return nil, err
		}

		for _, frac := range converted {
			tot = tot.Add(tot, frac)
		}

		if tot.Cmp(big.NewRat(1, 1)) == -1 {
			return nil, fmt.Errorf("threshold not statisfiable (%s)", c)
		}
		thresholds = append(thresholds, converted)
	}

	return &SigThreshold{conditions: thresholds}, nil
}
