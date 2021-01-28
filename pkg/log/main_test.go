package log

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

func TestOrder(t *testing.T) {
	assert := assert.New(t)
	l := New()

	e := l.Current()
	assert.Nil(e)

	e = l.Inception()
	assert.Nil(e)

	icp, err := event.NewEvent(event.WithType(event.ICP))
	assert.Nil(err)

	l.Events = append(l.Events, &event.Message{Event: icp})

	e, err = event.NewEvent(event.WithType(event.ROT), event.WithSequence(1))
	assert.Nil(err)

	l.Events = append(l.Events, &event.Message{Event: e})

	e, err = event.NewEvent(event.WithType(event.ROT), event.WithSequence(2))
	assert.Nil(err)

	l.Events = append(l.Events, &event.Message{Event: e})

	latest, err := event.NewEvent(event.WithType(event.ROT), event.WithSequence(3))
	assert.Nil(err)

	l.Events = append(l.Events, &event.Message{Event: latest})

	e = l.Inception()
	assert.Same(icp, e)

	e = l.Current()
	assert.Same(latest, e)
}

func TestVerifyAndApply(t *testing.T) {
	assert := assert.New(t)

	// play the events generated from the keripy implementation
	// TODO: move these to approved test vectors in main keri repo

	l := New()

	incept := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}`)
	inceptSig := []byte(`-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

	msg := &event.Message{Event: &event.Event{}}
	err := json.Unmarshal(incept, msg.Event)
	assert.Nil(err)

	sigs, err := derivation.ParseAttachedSignatures(bytes.NewBuffer(inceptSig))
	assert.Nil(err)
	assert.Len(sigs, 1)

	msg.Signatures = sigs

	err = l.Verify(msg)
	assert.Nil(err)

	err = l.Apply(msg)
	assert.Nil(err)
	assert.Len(l.Events, 1)

	rot := []byte(`{"v":"KERI10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}`)
	rotSig := []byte(`-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

	msg = &event.Message{Event: &event.Event{}}
	err = json.Unmarshal(rot, msg.Event)
	assert.Nil(err)

	sigs, err = derivation.ParseAttachedSignatures(bytes.NewBuffer(rotSig))
	assert.Nil(err)
	assert.Len(sigs, 1)

	msg.Signatures = sigs

	// Modify the event to be different - should not validate
	msg.Event.EventType = "invalid"

	err = l.Verify(msg)
	assert.NotNil(err)

	// back to normal, should work
	msg.Event.EventType = "rot"
	err = l.Verify(msg)
	assert.Nil(err)

	// invalid sequence - should not apply
	msg.Event.Sequence = "42"
	err = l.Apply(msg)
	if assert.NotNil(err) {
		assert.Equal("invalid sequence for new event", err.Error())
	}
	assert.Len(l.Events, 1)

	// invalid digest, should not apply
	msg.Event.Sequence = "1"
	msg.Event.Digest = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	err = l.Apply(msg)
	if assert.NotNil(err) {
		assert.Equal("invalid digest for new event", err.Error())
	}
	assert.Len(l.Events, 1)

	// Correct, should apply
	msg.Event.Digest = "E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc"
	err = l.Apply(msg)
	assert.Nil(err)
	assert.Len(l.Events, 2)

	ixn := []byte(`{"v":"KERI10JSON000098_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"2","t":"ixn","p":"ELWbb2Oun3FTpWZqHYmeefM5B-11nZQBsxPfufyjJHy4","a":[]}`)
	ixnSig := []byte(`-AABAAqxzoxk4rltuP41tB8wEpHFC4Yd1TzhOGfuhlylbDFAm73jB2emdvaLjUP6FrHxiPqS2CcbAWaVNsmii80KJEBw`)

	msg = &event.Message{Event: &event.Event{}}
	err = json.Unmarshal(ixn, msg.Event)
	assert.Nil(err)

	sigs, err = derivation.ParseAttachedSignatures(bytes.NewBuffer(ixnSig))
	assert.Nil(err)
	assert.Len(sigs, 1)

	msg.Signatures = sigs

	err = l.Verify(msg)
	assert.Nil(err)

	err = l.Apply(msg)
	assert.Nil(err)
	assert.Len(l.Events, 3)
}

func TestEscrow(t *testing.T) {
	assert := assert.New(t)

	keys, err := newKeys(3)
	if !assert.Nil(err) {
		return
	}

	prefixes := []prefix.Prefix{}
	for _, k := range keys {
		prefixes = append(prefixes, k.pre)
	}

	e, err := event.NewInceptionEvent(
		event.WithKeys(prefixes...),
		event.WithThreshold(3),
		event.WithDefaultVersion(event.JSON),
	)

	assert.Nil(err)

	l := New()
	err = l.Apply(&event.Message{Event: e})
	if !assert.Nil(err) || !assert.Len(l.Events, 1) {
		return
	}

	// create a valid next event
	serialized, err := e.Serialize()
	if !assert.Nil(err) {
		return
	}

	digest, err := event.DigestString(serialized, derivation.Blake3256)
	if !assert.Nil(err) {
		return
	}

	next, err := event.NewEvent(
		event.WithKeys(prefixes...),
		event.WithType(event.ROT),
		event.WithSequence(1),
		event.WithDigest(digest),
		event.WithThreshold(2),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	serialized, err = next.Serialize()
	if !assert.Nil(err) {
		return
	}

	nextDigest, err := event.DigestString(serialized, derivation.Blake3256)
	if !assert.Nil(err) {
		return
	}

	// attach a single sig (need two)
	// Doesn't need to be valid - we aren't running through the verification
	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached))
	if !assert.Nil(err) {
		return
	}
	sig.KeyIndex = 0
	// sigs := []*derivation.Derivation{sig}

	// event has no sigs, so should be escrowed
	err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Escrow, 1)
	if !assert.Contains(l.Escrow, nextDigest) || !assert.Len(l.Escrow[nextDigest].Signatures, 1) {
		return
	}

	// Apply the event again - this should "escrow" but the escrow length should not increase
	err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Events, 1)
	if !assert.Contains(l.Escrow, nextDigest) || !assert.Len(l.Escrow[nextDigest].Signatures, 1) {
		return
	}

	// Change the signature key, this is equal to adding another signature
	sig.KeyIndex = 1

	// 2 of 3 sigs, should escrow
	err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Events, 1)
	if !assert.Contains(l.Escrow, nextDigest) || !assert.Len(l.Escrow[nextDigest].Signatures, 2) {
		return
	}

	// another key sig
	sig.KeyIndex = 2

	// 3 of 3, should apply
	err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Events, 2)
	assert.Empty(l.Escrow)
}

func TestMergeSignatures(t *testing.T) {
	assert := assert.New(t)

	sigs := []derivation.Derivation{}

	d1, _ := derivation.New(derivation.WithCode(derivation.Blake2b256))
	d1.Derive([]byte("asdf"))
	d1.KeyIndex = 0

	new := []derivation.Derivation{*d1}

	sigs = mergeSignatures(nil, new)
	assert.Len(sigs, 1)

	d2, _ := derivation.New(derivation.WithCode(derivation.Blake2b256))
	d2.Derive([]byte("fdsa"))
	d2.KeyIndex = 1

	sigs = mergeSignatures(sigs, []derivation.Derivation{*d2})
	assert.Len(sigs, 2)
}

type basicKeys struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	pre  prefix.Prefix
}

func newKeys(num int) ([]*basicKeys, error) {

	var keys []*basicKeys

	for i := 0; i < num; i++ {
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		basicDerivation, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub))
		if err != nil {
			return nil, err
		}

		basicPre := prefix.New(basicDerivation)

		keys = append(keys, &basicKeys{priv: edPriv, pub: edPub, pre: basicPre})
	}

	return keys, nil
}
