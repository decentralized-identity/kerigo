package event

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/stretchr/testify/assert"
)

func TestSigThreshold(t *testing.T) {
	assert := assert.New(t)

	st, err := NewSigThreshold(-1)
	assert.Nil(st)
	assert.Equal("threshold must be >= 0", err.Error())

	st, err = NewSigThreshold(0)
	assert.Nil(err)
	assert.Equal([][]*big.Rat{{big.NewRat(0, 1)}}, st.conditions)

	st, err = NewSigThreshold(1)
	assert.Nil(err)
	assert.Equal([][]*big.Rat{{big.NewRat(1, 1)}}, st.conditions)

	st, err = NewSigThreshold(4)
	assert.Nil(err)
	assert.Equal([][]*big.Rat{{big.NewRat(4, 1)}}, st.conditions)

	// This is a "simple" threshold, i.e. not weighted
	assert.False(st.Weighted())

	// thresholds must be > 1
	st, err = NewWeighted()
	assert.Nil(st)
	assert.Equal("threshold not satifiable: sum of weights must be greather than 1", err.Error())

	st, err = NewWeighted("1/2")
	assert.Nil(st)
	assert.Equal("threshold not satifiable: sum of weights must be greather than 1", err.Error())

	st, err = NewWeighted("1/2", "1/4")
	assert.Nil(st)
	assert.Equal("threshold not satifiable: sum of weights must be greather than 1", err.Error())

	// Invalid fractional representation
	st, err = NewWeighted("asdf")
	assert.Nil(st)
	assert.Equal("unable to parse condition asdf: Rat.Scan: invalid syntax", err.Error())

	// No negative weights
	st, err = NewWeighted("1/4", "1/2", "-1/4")
	assert.Nil(st)
	assert.Equal("thresholds must be >= 0", err.Error())

	// different combinations that combined are >1
	st, err = NewWeighted("1/2", "1/2")
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 2)
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
	}

	st, err = NewWeighted("1/2", "1/4", "1/4")
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 3)
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))
	}

	st, err = NewWeighted("1/2", "1/4", "1/4", "1")
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 4)
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
	}

	// this is a weighted threshold
	assert.True(st.Weighted())

	// All thresholds must be staisfiable since they are treated as "AND" condiitons
	st, err = NewMultiWeighted([]string{"1/2", "1/4"}, []string{"1"})
	assert.Nil(st)
	assert.Equal("threshold not statisfiable ([1/2 1/4])", err.Error())

	st, err = NewMultiWeighted([]string{"1/2", "1/4", "1/4"}, []string{"-1"})
	assert.Nil(st)
	assert.Equal("thresholds must be >= 0", err.Error())

	st, err = NewMultiWeighted([]string{"1/2", "1/4", "1/4"}, []string{"1"})
	assert.Nil(err)
	if assert.Len(st.conditions, 2) {
		assert.Len(st.conditions[0], 3)
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))

		assert.Len(st.conditions[1], 1)
		assert.Contains(st.conditions[1], big.NewRat(1, 1))
	}

	// this is a weighted threshold
	assert.True(st.Weighted())

}

func TestJSONMarshalSigThreshold(t *testing.T) {
	assert := assert.New(t)

	st, _ := NewSigThreshold(1)
	j, err := json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`"1"`), j)

	st, _ = NewSigThreshold(25)
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`"25"`), j)

	st = &SigThreshold{}
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`"0"`), j)

	st, _ = NewWeighted("1", "1/2", "1/4")
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`["1","1/2","1/4"]`), j)

	st, _ = NewWeighted("1")
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`"1"`), j)

	st, _ = NewMultiWeighted([]string{"1", "1/4", "1/2"}, []string{"1"})
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`[["1","1/4","1/2"],["1"]]`), j)

	st, _ = NewMultiWeighted([]string{"1", "1/4", "1/2"})
	j, err = json.Marshal(st)
	assert.Nil(err)
	assert.Equal([]byte(`["1","1/4","1/2"]`), j)
}

func TestJSONUnmarshalSigThreshold(t *testing.T) {
	assert := assert.New(t)

	st := &SigThreshold{}
	err := json.Unmarshal([]byte(`"1"`), st)

	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 1)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
	}

	st = &SigThreshold{}
	err = json.Unmarshal([]byte(`["1"]`), st)

	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 1)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
	}

	st = &SigThreshold{}
	err = json.Unmarshal([]byte(`["1","1/4","1/2"]`), st)
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 3)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
	}

	st = &SigThreshold{}
	err = json.Unmarshal([]byte(`[["1","1/4","1/2"],["1"]]`), st)
	assert.Nil(err)
	if assert.Len(st.conditions, 2) {
		assert.Len(st.conditions[0], 3)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
		assert.Len(st.conditions[1], 1)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
	}

	// if you throw bad stuff at us, we do our best to ignore your stupidity
	// (i.e. pick one way and go with it - either weighted, or multi-weighted, but
	// you cantz have both)
	st = &SigThreshold{}
	err = json.Unmarshal([]byte(`[["1","1/4","1/2"],"1"]`), st)
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 3)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
		assert.Contains(st.conditions[0], big.NewRat(1, 4))
		assert.Contains(st.conditions[0], big.NewRat(1, 2))
	}

	st = &SigThreshold{}
	err = json.Unmarshal([]byte(`["1", ["1","1/4","1/2"]]`), st)
	assert.Nil(err)
	if assert.Len(st.conditions, 1) {
		assert.Len(st.conditions[0], 1)
		assert.Contains(st.conditions[0], big.NewRat(1, 1))
	}
}

func TestSatisfied(t *testing.T) {
	assert := assert.New(t)

	st, _ := NewSigThreshold(3)
	sigs := []derivation.Derivation{{KeyIndex: 0}}
	assert.False(st.Satisfied(sigs))

	sigs = []derivation.Derivation{{KeyIndex: 0}, {KeyIndex: 1}}
	assert.False(st.Satisfied(sigs))

	sigs = []derivation.Derivation{{KeyIndex: 0}, {KeyIndex: 1}, {KeyIndex: 2}}
	assert.True(st.Satisfied(sigs))

	st, _ = NewWeighted("1/2", "1/4", "1/4")
	assert.True(st.Satisfied(sigs))

	sigs = []derivation.Derivation{{KeyIndex: 0}}
	assert.False(st.Satisfied(sigs))

	sigs = []derivation.Derivation{{KeyIndex: 0}, {KeyIndex: 1}, {KeyIndex: 5}}
	assert.False(st.Satisfied(sigs))

	sigs = []derivation.Derivation{{KeyIndex: 2}, {KeyIndex: 1}}
	assert.False(st.Satisfied(sigs))

	st, _ = NewMultiWeighted([]string{"1/2", "1/2", "1/4", "1/4", "1/4", "1/4"}, []string{"1", "1"})

	// meet the second but not the first
	sigs = []derivation.Derivation{{KeyIndex: 1}, {KeyIndex: 4}}
	assert.False(st.Satisfied(sigs))

	// meet the first but not the second
	sigs = []derivation.Derivation{{KeyIndex: 2}, {KeyIndex: 3}, {KeyIndex: 4}, {KeyIndex: 5}}
	assert.False(st.Satisfied(sigs))

	// pass
	sigs = []derivation.Derivation{{KeyIndex: 0}, {KeyIndex: 2}, {KeyIndex: 3}, {KeyIndex: 4}, {KeyIndex: 5}}
	assert.True(st.Satisfied(sigs))
}
