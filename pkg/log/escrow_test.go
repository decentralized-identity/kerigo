package log

import (
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/stretchr/testify/assert"
)

func TestEscrow(t *testing.T) {
	assert := assert.New(t)

	esc := Escrow(map[string]*event.Message{})

	keys, err := newKeys(3)
	if !assert.Nil(err) {
		return
	}
	prefixes := []prefix.Prefix{}
	for _, k := range keys {
		prefixes = append(prefixes, k.pre)
	}

	// Create an event and add a signature
	icp, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(prefixes...))
	assert.Nil(err)

	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached))
	if !assert.Nil(err) {
		return
	}
	sig.KeyIndex = 0

	err = esc.Add(&event.Message{Event: icp, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(esc, 1)

	// Applying the same event should not increase escrow size or signature size
	err = esc.Add(&event.Message{Event: icp, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	if assert.Len(esc, 1) {
		m, err := esc.Get(icp)
		assert.Nil(err)
		assert.Equal(icp, m.Event)
		assert.Len(m.Signatures, 1)
	}

	sig2, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached))
	if !assert.Nil(err) {
		return
	}
	sig2.KeyIndex = 1

	// applying the same message again, but with a different signature, should add the sig
	err = esc.Add(&event.Message{Event: icp, Signatures: []derivation.Derivation{*sig2}})
	assert.Nil(err)
	if assert.Len(esc, 1) {
		m, err := esc.Get(icp)
		assert.Nil(err)
		assert.Equal(icp, m.Event)
		assert.Len(m.Signatures, 2)
	}

	// create another event with different keys (though same in other respects)
	keys2, err := newKeys(3)
	if !assert.Nil(err) {
		return
	}
	prefixes2 := []prefix.Prefix{}
	for _, k := range keys2 {
		prefixes2 = append(prefixes2, k.pre)
	}

	icp2, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(prefixes2...))
	assert.Nil(err)

	// adding another event - same type, seq, etc, but different keys, so this is a "different" event.
	// Escrow should maintain them separately
	err = esc.Add(&event.Message{Event: icp2, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	if assert.Len(esc, 2) {
		m, err := esc.Get(icp2)
		assert.Equal(icp2, m.Event)
		assert.Nil(err)
		assert.Len(m.Signatures, 1)
	}

	// Add several more events to the escrow
	ixn, err := event.NewEvent(
		event.WithKeys(prefixes...),
		event.WithSequence(1),
		event.WithType(event.IXN),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	err = esc.Add(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(esc, 3)

	ixn, err = event.NewEvent(
		event.WithKeys(prefixes...),
		event.WithSequence(2),
		event.WithType(event.IXN),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	err = esc.Add(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(esc, 4)

	ixn, err = event.NewEvent(
		event.WithKeys(prefixes...),
		event.WithSequence(3),
		event.WithType(event.IXN),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	err = esc.Add(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(esc, 5)

	// get the events for the sequence
	msgs := esc.ForSequence(3)
	if assert.Len(msgs, 1) {
		assert.Equal(msgs[0].Event, ixn)
		assert.Len(msgs[0].Signatures, 1)
	}

	msgs = esc.ForSequence(0)
	assert.Len(msgs, 2)

	// Clear events
	esc.Clear(*ixn)
	assert.Len(esc, 4)
	msgs = esc.ForSequence(3)
	assert.Empty(msgs)

	// this should return
	leftovers, err := esc.Clear(*icp)
	assert.Nil(err)
	if assert.Len(leftovers, 1) {
		assert.Equal(leftovers[0].Event, icp2)
	}
	assert.Len(esc, 2)
	msgs = esc.ForSequence(0)
	assert.Empty(msgs)
}
