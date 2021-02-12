package log

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

// TODO: move these to approved test vectors in main keri repo

var incept = []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}`)
var inceptSig = []byte(`-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)
var rot = []byte(`{"v":"KERI10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}`)
var rotSig = []byte(`-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)
var ixn = []byte(`{"v":"KERI10JSON000098_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"2","t":"ixn","p":"ELWbb2Oun3FTpWZqHYmeefM5B-11nZQBsxPfufyjJHy4","a":[]}`)
var ixnSig = []byte(`-AABAAqxzoxk4rltuP41tB8wEpHFC4Yd1TzhOGfuhlylbDFAm73jB2emdvaLjUP6FrHxiPqS2CcbAWaVNsmii80KJEBw`)

func TestOrder(t *testing.T) {
	assert := assert.New(t)

	db := mem.New()
	l := New("pre", db)

	e := l.Current()
	assert.Nil(e)

	e = l.Inception()
	assert.Nil(e)

	icp, err := event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ICP))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: icp})
	assert.Nil(err)

	e, err = event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(1))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: e})
	assert.Nil(err)

	e, err = event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(2))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: e})

	latest, err := event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(3))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: latest})
	assert.Nil(err)

	e = l.Inception()
	assert.Same(icp, e)

	e = l.Current()
	assert.Same(latest, e)
}

func TestEventAt(t *testing.T) {
	assert := assert.New(t)
	db := mem.New()
	l := New("pre", db)
	evts := []*event.Message{
		{
			Event: &event.Event{Prefix: "pre", Sequence: fmt.Sprintf("%x", 0)},
		},
		{
			Event: &event.Event{Prefix: "pre", Sequence: fmt.Sprintf("%x", 1)},
		},
		{
			Event: &event.Event{Prefix: "pre", Sequence: fmt.Sprintf("%x", 2)},
		},
		{
			Event: &event.Event{Prefix: "pre", Sequence: fmt.Sprintf("%x", 3)},
		},
	}

	for _, evt := range evts {
		err := db.LogEvent(evt)
		assert.NoError(err)
	}

	evnt := l.EventAt(20)
	assert.Nil(evnt)

	evnt = l.EventAt(-2)
	assert.Nil(evnt)

	evnt = l.EventAt(2)
	if assert.NotNil(evnt) {
		assert.Equal(fmt.Sprintf("%x", 2), evnt.Event.Sequence)
	}

	evnt = l.EventAt(0)
	if assert.NotNil(evnt) {
		assert.Equal(fmt.Sprintf("%x", 0), evnt.Event.Sequence)
	}

	evnt = l.EventAt(3)
	if assert.NotNil(evnt) {
		assert.Equal(fmt.Sprintf("%x", 3), evnt.Event.Sequence)
	}

}

func TestVerifyAndApply(t *testing.T) {
	assert := assert.New(t)
	db := mem.New()

	msg := &event.Message{Event: &event.Event{}}
	err := json.Unmarshal(incept, msg.Event)
	if !assert.Nil(err) {
		return
	}

	l := New(msg.Event.Prefix, db)
	sigs, err := derivation.ParseAttachedSignatures(bytes.NewBuffer(inceptSig))
	assert.Nil(err)
	assert.Len(sigs, 1)

	msg.Signatures = sigs

	err = l.Verify(msg)
	assert.Nil(err)

	// apply the inception event
	err = l.Apply(msg)
	assert.Nil(err)
	assert.Equal(l.Size(), 1)

	msg = &event.Message{Event: &event.Event{}}
	err = json.Unmarshal(rot, msg.Event)
	assert.Nil(err)

	// #2 rotations
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

	// invalid sequence - should be added to the pending escrow
	msg.Event.Sequence = "42"
	err = l.Apply(msg)
	assert.Nil(err)
	assert.Len(l.Pending, 1)
	assert.Equal(l.Size(), 1)

	// apply again, should not change events length
	err = l.Apply(msg)
	assert.Nil(err)
	if assert.Equal(l.db.LogSize(l.prefix), 1) {
		// assert.Len(l.Events[0].Signatures, 1)
	}

	// Interaction event

	// TODO: need test vectors for this.

	// msg = &event.Message{Event: &event.Event{}}
	// err = json.Unmarshal(ixn, msg.Event)
	// assert.Nil(err)

	// sigs, err = derivation.ParseAttachedSignatures(bytes.NewBuffer(ixnSig))
	// assert.Nil(err)
	// assert.Len(sigs, 1)

	// msg.Signatures = sigs

	// err = l.Verify(msg)
	// assert.Nil(err)
}

func TestMultiSigApply(t *testing.T) {
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
		event.WithPrefix("pre"),
		event.WithKeys(prefixes...),
		event.WithThreshold(3),
		event.WithDefaultVersion(event.JSON),
	)

	assert.Nil(err)

	db := mem.New()
	l := New("pre", db)
	err = l.Apply(&event.Message{Event: e})
	if !assert.Nil(err) || !assert.Equal(l.Size(), 1) {
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
		event.WithPrefix("pre"),
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

	// nextDigest, err := event.DigestString(serialized, derivation.Blake3256)
	// if !assert.Nil(err) {
	// 	return
	// }

	// create a bad next event
	badNext, err := event.NewEvent(
		event.WithPrefix("pre"),
		event.WithKeys(prefixes...),
		event.WithType(event.IXN),
		event.WithSequence(1),
		event.WithDigest(digest),
		event.WithThreshold(3),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	serialized, err = badNext.Serialize()
	if !assert.Nil(err) {
		return
	}

	// badNextDigest, err := event.DigestString(serialized, derivation.Blake3256)
	// if !assert.Nil(err) {
	// 	return
	// }

	// attach a single sig (need two)
	// Doesn't need to be valid - we aren't running through the verification
	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached))
	if !assert.Nil(err) {
		return
	}
	sig.KeyIndex = 0

	// event has no sigs, so should be escrowed
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Pending, 1)
	// if !assert.Contains(l.Pending, nextDigest) || !assert.Len(l.Pending[nextDigest].Signatures, 1) {
	// 	return
	// }

	// Apply the event again - this should "escrow" but the escrow length should not increase
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Events, 1)
	// if !assert.Contains(l.Pending, nextDigest) || !assert.Len(l.Pending[nextDigest].Signatures, 1) {
	// 	return
	// }

	// // Change the signature key, this is equal to adding another signature
	// sig.KeyIndex = 1

	// // 2 of 3 sigs, should escrow
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Events, 1)
	// if !assert.Contains(l.Pending, nextDigest) || !assert.Len(l.Pending[nextDigest].Signatures, 2) {
	// 	return
	// }

	// // another key sig
	// sig.KeyIndex = 2

	// // 3 of 3, should apply
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Events, 2)
	// assert.Empty(l.Pending)
	// assert.Len(l.Events[1].Signatures, 3)

	// // add a 4th signature = this should simply tack on to our existing sig list in the log
	// sig.KeyIndex = 3

	// // 4 of 3, should apply
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Events, 2)
	// assert.Empty(l.Pending)
	// assert.Len(l.Events[1].Signatures, 4)

	// // send through our bad event
	// err = l.Apply(&event.Message{Event: badNext, Signatures: []derivation.Derivation{*sig}})
	// assert.NotNil(err)
	// assert.Len(l.Events, 2)
	// assert.Empty(l.Pending)
	// assert.Contains(l.Duplicitous, badNextDigest)
}

func TestEscrowApply(t *testing.T) {
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
		event.WithPrefix("pre"),
		event.WithKeys(prefixes...),
		event.WithThreshold(2),
		event.WithDefaultVersion(event.JSON),
	)

	assert.Nil(err)

	db := mem.New()
	l := New("pre", db)
	err = l.Apply(&event.Message{Event: e})
	if !assert.Nil(err) || !assert.Equal(l.Size(), 1) {
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
		event.WithPrefix("pre"),
		event.WithKeys(prefixes...),
		event.WithType(event.ROT),
		event.WithSequence(1),
		event.WithDigest(digest),
		event.WithThreshold(1),
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

	// create a valid event for after next.
	nextNext, err := event.NewEvent(
		event.WithPrefix("pre"),
		event.WithKeys(prefixes...),
		event.WithType(event.ROT),
		event.WithSequence(2),
		event.WithDigest(nextDigest),
		event.WithThreshold(1),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	// create a duplicitous nextNext event
	dupNextNext, err := event.NewEvent(
		event.WithPrefix("pre"),
		event.WithKeys(prefixes[0]),
		event.WithType(event.ROT),
		event.WithSequence(2),
		event.WithDigest(nextDigest),
		event.WithThreshold(3),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	// attach a single sig (need two)
	// Doesn't need to be valid - we aren't running through the verification
	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached))
	if !assert.Nil(err) {
		return
	}
	sig.KeyIndex = 0

	// apply nextNext - it will be out of order, so should escrow under pending.
	err = l.Apply(&event.Message{Event: nextNext, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Pending, 1)
	assert.Equal(l.Size(), 1)

	// apply dupNextNext - it will be out of order, so should also escrow under pending.
	err = l.Apply(&event.Message{Event: dupNextNext, Signatures: []derivation.Derivation{*sig}})
	assert.Nil(err)
	assert.Len(l.Pending, 2)
	assert.Equal(l.Size(), 1)

	// apply Next with only one sig. This should escrow to pending
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Pending, 3)
	// assert.Len(l.Events, 1)

	// apply next with another sig, this will apply it
	// this should also apply the pending nextNext event since
	// next has a threshold of 1 and we already have that many
	// signatures in escrow. It should also put dupNextNext into the
	// duplicitous escrow since it arrived after nextNext.
	// Thus, we should have all 3 events applied and nothing in pending
	// sig.KeyIndex = 1
	// err = l.Apply(&event.Message{Event: next, Signatures: []derivation.Derivation{*sig}})
	// assert.Nil(err)
	// assert.Len(l.Pending, 0)
	// if assert.Len(l.Events, 3) {
	// 	assert.Equal(nextNext, l.Events[2].Event)
	// }
	// if assert.Len(l.Duplicitous, 1) {
	// 	m, err := l.Duplicitous.Get(dupNextNext)
	// 	assert.Nil(err)
	// 	assert.Equal(dupNextNext, m.Event)
	// }

}

func TestMergeSignatures(t *testing.T) {
	assert := assert.New(t)

	d1, _ := derivation.New(derivation.WithCode(derivation.Blake2b256))
	d1.Derive([]byte("asdf"))
	d1.KeyIndex = 0

	new := []derivation.Derivation{*d1}

	sigs := mergeSignatures(nil, new)
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

func TestReceipts(t *testing.T) {
	k, err := newKeys(2)
	assert.NoError(t, err)

	icp, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(k[0].pre))
	assert.NoError(t, err)
	est, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(k[1].pre))
	assert.NoError(t, err)

	vrc, err := event.TransferableReceipt(icp, est, derivation.Blake3256)
	assert.NoError(t, err)

	msg := &event.Message{
		Event: icp,
	}

	db := mem.New()
	kel := New(icp.Prefix, db)
	err = kel.Apply(msg)

	assert.NoError(t, err)

	msg = &event.Message{
		Event: vrc,
	}
	err = kel.ApplyReceipt(msg)
	assert.NoError(t, err)

	rcpts := kel.ReceiptsForEvent(icp)
	assert.Len(t, rcpts, 1)
}

func TestKeyState(t *testing.T) {
	assert := assert.New(t)

	evts := []*event.Message{
		{Event: &event.Event{
			Prefix:    "pre",
			Version:   event.DefaultVersionString(event.JSON),
			EventType: "icp",
			Sequence:  "0",
			Keys:      []string{"k1.1", "k1.2", "k1.3"},
			Next:      "next1",
			Witnesses: []string{"w1"},
		}},
		{Event: &event.Event{
			Prefix:     "pre",
			Version:    event.DefaultVersionString(event.JSON),
			EventType:  "rot",
			Sequence:   "1",
			Keys:       []string{"k2.1", "k2.2", "k2.3"},
			Next:       "next2",
			AddWitness: []string{"w2", "w3", "w4"},
		}},
		{Event: &event.Event{
			Prefix:    "pre",
			Version:   event.DefaultVersionString(event.JSON),
			EventType: "rot",
			Sequence:  "2",
			Keys:      []string{"k2.1", "k2.2", "k2.3"},
			Next:      "next2",
		}},

		{Event: &event.Event{
			Prefix:    "pre",
			Version:   event.DefaultVersionString(event.JSON),
			EventType: "ixn",
			Sequence:  "3",
			Keys:      []string{"k2.1", "k2.2", "k2.3"},
			Next:      "next2",
		}},

		{Event: &event.Event{
			Prefix:        "pre",
			Version:       event.DefaultVersionString(event.JSON),
			EventType:     "rot",
			Sequence:      "4",
			Keys:          []string{"k3.1"},
			Next:          "next3",
			RemoveWitness: []string{"w3"},
			AddWitness:    []string{"w42"},
		}},

		{Event: &event.Event{
			Prefix:    "pre",
			Version:   event.DefaultVersionString(event.JSON),
			EventType: "ixn",
			Sequence:  "5",
			Keys:      []string{"k2.1", "k2.2", "k2.3"},
			Next:      "next2",
		}},
	}

	db := mem.New()
	l := New("pre", db)

	for _, evt := range evts {
		err := db.LogEvent(evt)
		assert.NoError(err)
	}

	est := l.EstablishmentEvents()
	assert.Len(est, 4)

	ks, err := l.KeyState()
	assert.Nil(err)

	assert.Equal([]string{"k3.1"}, ks.Keys)
	assert.Equal("next3", ks.Next)
	assert.Equal([]string{"w1", "w2", "w4", "w42"}, ks.Witnesses)
	if assert.NotNil(ks.LastEstablishment) {
		assert.Equal("4", ks.LastEstablishment.Sequence)
		assert.Equal("EtIfYUO5H0zRUkzMfi1DHTMUWh0fIrLuEuaDHZc7jz2k", ks.LastEstablishment.Digest)
	}

	if assert.NotNil(ks.LastEvent) {
		assert.Equal("5", ks.LastEvent.Sequence)
		assert.Equal("E-8IKj55f68V-ryKv9fuxu8WaLOUVux8uX_yD6NiQYlE", ks.LastEvent.Digest)
		assert.Equal("ixn", ks.LastEvent.EventType)
	}

}
