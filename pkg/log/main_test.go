package log

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/decentralized-identity/kerigo/pkg/test"
	testkms "github.com/decentralized-identity/kerigo/pkg/test/kms"
)

// TODO: move these to approved test vectors in main keri repo
var (
	secrets = []string{
		"AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw",
		"AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ",
		"AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM",
		"AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs",
		"Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k",
		"Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8",
		"AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc",
		"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s",
	}
)

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

	err = db.LogEvent(&event.Message{Event: icp}, true)
	assert.Nil(err)

	e, err = event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(1))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: e}, true)
	assert.Nil(err)

	e, err = event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(2))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: e}, true)
	assert.Nil(err)

	latest, err := event.NewEvent(event.WithPrefix("pre"), event.WithType(event.ROT), event.WithSequence(3))
	assert.Nil(err)

	err = db.LogEvent(&event.Message{Event: latest}, true)
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
		err := db.LogEvent(evt, true)
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

	kms := testkms.GetKMS(t, secrets, mem.New())
	thresh, _ := event.NewSigThreshold(1)
	icp := test.InceptionFromSecrets(t, []string{secrets[0]}, []string{secrets[1]}, *thresh, *thresh)

	ser, err := icp.Serialize()
	assert.Nil(err)

	der, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms.Signer()))
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	msg := &event.Message{Event: icp, Signatures: []derivation.Derivation{*der}}
	l := New(msg.Event.Prefix, db)
	assert.NoError(l.Apply(msg))
	assert.Equal(1, l.Size())

	// Interaction
	ixn, err := event.NewInteractionEvent(
		event.WithSequence(1),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)

	// Error Cases to test:
	//
	// No signatures
	// Valid signatures but no digest
	// Valid signatures but invalid digest

	// No signatures - these get silently ignored
	assert.NoError(l.Apply(&event.Message{Event: ixn}))
	assert.Equal(l.Size(), 1)

	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	// Valid sig, no digest
	err = l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}})
	if assert.Error(err) {
		assert.Equal("unable to determine digest derivation (unable to determine derivation (invalid prefix length))", err.Error())
	}
	assert.Equal(1, l.Size())

	// Valid sig invalid digest
	ixn.PriorEventDigest = fmt.Sprintf("%s%s", derivation.Blake3256.String(), strings.Repeat("A", derivation.Blake3256.PrefixBase64Length()-1))
	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	err = l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}})
	if assert.Error(err) {
		assert.Equal("invalid digest for new event", err.Error())
	}
	assert.Equal(1, l.Size())
	//assert.Len(l.Duplicitous, 1)

	// Valid Sig/Digest - should apply
	ixn.PriorEventDigest, err = icp.GetDigest()
	assert.Nil(err)
	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}}))
	assert.Equal(2, l.Size())

	// applying the same event again should not change the log
	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}}))
	assert.Equal(2, l.Size())
	//assert.Len(l.Duplicitous, 1)
	//assert.Len(l.Pending, 0)

	// Future events should be escrowed.
	// Two added: one without a valid digest - this one will be
	// added to the duplicitous escrow when processed
	// The second will have a valid digest - that one shoudl be added to the
	// the log automatically when the interveining event gets applied

	// Future event
	ixn, err = event.NewInteractionEvent(
		event.WithSequence(3),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)
	ixn.PriorEventDigest = fmt.Sprintf("%s%s", derivation.Blake3256.String(), strings.Repeat("A", derivation.Blake3256.PrefixBase64Length()-1))

	// No signatures - should silently ignore
	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{}}))
	assert.Equal(2, l.Size())
	//assert.Len(l.Pending, 0)

	// Should add to pending
	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}}))
	assert.Equal(2, l.Size())
	//assert.Equal(1, len(l.Pending))

	// Rotate the Keys and use the new key to sign a future event
	// that will become valid after the applciation of the ROT event
	assert.NoError(kms.Rotate())
	der, err = derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms.Signer()))
	assert.Nil(err)

	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(kms.PublicKey()))
	assert.NoError(err)
	keyPre := prefix.New(keyDer)

	rot, err := event.NewRotationEvent(
		event.WithPrefix(icp.Prefix),
		event.WithSequence(2),
		event.WithKeys(keyPre),
		event.WithNext("1", derivation.Blake3256, prefix.New(kms.Next())),
	)
	assert.Nil(err)

	rot.PriorEventDigest, err = l.Current().GetDigest()
	assert.Nil(err)

	// Future event
	ixn, err = event.NewInteractionEvent(
		event.WithSequence(3),
		event.WithPrefix(icp.Prefix),
		event.WithSeals(event.SealArray{&event.Seal{Root: "asdf"}}),
	)
	assert.Nil(err)

	ixn.PriorEventDigest, err = rot.GetDigest()
	assert.Nil(err)
	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)
	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*der}}))
	assert.Equal(2, l.Size())
	//assert.Len(l.Pending, 2)

	ser, err = rot.Serialize()
	assert.Nil(err)
	_, err = der.Derive(ser)
	assert.Nil(err)

	// Will apply ROT, duplicitous escrow event with invalid signature, and process valid pending
	assert.Error(l.Apply(&event.Message{Event: rot, Signatures: []derivation.Derivation{*der}}))
	//assert.Equal(4, l.Size())
	//assert.Len(l.Pending, 0)
	//assert.Len(l.Duplicitous, 2)

	// Confirm the last event is the correct one
	//crnt := l.Current()
	//assert.Equal(ixn, crnt)
}

func TestMultiSigApply(t *testing.T) {
	assert := assert.New(t)

	db := mem.New()

	kms1 := testkms.GetKMS(t, secrets[:2], mem.New())
	sigDer1, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms1.Signer()))
	assert.Nil(err)
	kms2 := testkms.GetKMS(t, secrets[3:5], mem.New())
	sigDer2, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms2.Signer()))
	sigDer2.KeyIndex = 1
	assert.Nil(err)
	kms3 := testkms.GetKMS(t, secrets[6:], mem.New())
	sigDer3, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms3.Signer()))
	sigDer3.KeyIndex = 2
	assert.Nil(err)

	threshold, err := event.NewMultiWeighted([]string{"1/2", "1/2", "1"}, []string{"1"})
	assert.Nil(err)

	icp := test.InceptionFromSecrets(
		t,
		[]string{secrets[0], secrets[3], secrets[6]},
		[]string{secrets[1], secrets[4], secrets[7]},
		*threshold,
		*threshold,
	)

	ser, err := icp.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)
	_, err = sigDer2.Derive(ser)
	assert.Nil(err)
	_, err = sigDer3.Derive(ser)
	assert.Nil(err)

	msg := &event.Message{Event: icp, Signatures: []derivation.Derivation{*sigDer1, *sigDer2, *sigDer3}}
	l := New(msg.Event.Prefix, db)
	assert.NoError(l.Apply(msg))
	assert.Equal(1, l.Size())

	// interaction event with all necessary signatures provided
	ixn, err := event.NewInteractionEvent(
		event.WithSequence(1),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)
	ixn.PriorEventDigest, err = icp.GetDigest()
	assert.Nil(err)

	ser, err = ixn.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)
	_, err = sigDer2.Derive(ser)
	assert.Nil(err)
	_, err = sigDer3.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn, Signatures: []derivation.Derivation{*sigDer1, *sigDer2, *sigDer3}}))
	assert.Equal(2, l.Size())
	//assert.Len(l.Pending, 0)

	// event with async signature receipt
	ixn2, err := event.NewInteractionEvent(
		event.WithSequence(2),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)
	ixn2.PriorEventDigest, err = ixn.GetDigest()
	assert.Nil(err)

	ser, err = ixn2.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)
	_, err = sigDer2.Derive(ser)
	assert.Nil(err)
	_, err = sigDer3.Derive(ser)
	assert.Nil(err)

	// Not enough sigs
	assert.Error(l.Apply(&event.Message{Event: ixn2, Signatures: []derivation.Derivation{*sigDer1}}))
	assert.Equal(2, l.Size())
	//assert.Len(l.Pending, 1)

	// enough. apply.
	//assert.NoError(l.Apply(&event.Message{Event: ixn2, Signatures: []derivation.Derivation{*sigDer3}}))
	//assert.Equal(3, l.Size())
	//assert.Len(l.Pending, 0)

	// apply a late signature
	//assert.NoError(l.Apply(&event.Message{Event: ixn2, Signatures: []derivation.Derivation{*sigDer2}}))
	//assert.Equal(3, l.Size())
	//assert.Len(l.Pending, 0)
	//assert.Len(l.EventAt(2).Signatures, 3)

	// 3rd event
	// event with async signature receipt
	ixn3, err := event.NewInteractionEvent(
		event.WithSequence(3),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)
	ixn3.PriorEventDigest, err = ixn2.GetDigest()
	assert.Nil(err)

	// Create double future events
	// 4.a will insert the first sig
	// 4.b will finish all necessary sigs first
	// 4.b will get apply, 4.a will be duplicitous escrowed
	ixn4a, err := event.NewInteractionEvent(
		event.WithSequence(4),
		event.WithPrefix(icp.Prefix),
	)
	assert.Nil(err)
	ixn4a.PriorEventDigest, err = ixn3.GetDigest()
	assert.Nil(err)

	ixn4b, err := event.NewInteractionEvent(
		event.WithSequence(4),
		event.WithPrefix(icp.Prefix),
		event.WithSeals(event.SealArray{&event.Seal{Root: "asdf"}}),
	)
	assert.Nil(err)
	ixn4b.PriorEventDigest, err = ixn3.GetDigest()
	assert.Nil(err)

	ser, err = ixn4a.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn4a, Signatures: []derivation.Derivation{*sigDer1}}))
	//assert.Equal(3, l.Size())
	//assert.Len(l.Pending, 1)

	ser, err = ixn4b.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)
	_, err = sigDer2.Derive(ser)
	assert.Nil(err)
	_, err = sigDer3.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn4b, Signatures: []derivation.Derivation{*sigDer1}}))
	//assert.Equal(3, l.Size())
	//assert.Len(l.Pending, 2)

	assert.NoError(l.Apply(&event.Message{Event: ixn4b, Signatures: []derivation.Derivation{*sigDer3}}))
	//assert.Equal(3, l.Size())
	//assert.Len(l.Pending, 2)

	// apply 3, 4b should get applied
	ser, err = ixn3.Serialize()
	assert.Nil(err)
	_, err = sigDer1.Derive(ser)
	assert.Nil(err)
	_, err = sigDer2.Derive(ser)
	assert.Nil(err)
	_, err = sigDer3.Derive(ser)
	assert.Nil(err)

	assert.NoError(l.Apply(&event.Message{Event: ixn3, Signatures: []derivation.Derivation{*sigDer1, *sigDer2, *sigDer3}}))
	//assert.Equal(5, l.Size())
	//assert.Len(l.Pending, 0)
	//assert.Len(l.Duplicitous, 1)
	//assert.Equal(ixn4b, l.Current())
}

func TestMergeSignatures(t *testing.T) {
	assert := assert.New(t)

	d1, _ := derivation.New(derivation.WithCode(derivation.Blake2b256))
	_, err := d1.Derive([]byte("asdf"))
	assert.Nil(err)
	d1.KeyIndex = 0

	new := []derivation.Derivation{*d1}

	sigs := mergeSignatures(nil, new)
	assert.Len(sigs, 1)

	d2, _ := derivation.New(derivation.WithCode(derivation.Blake2b256))
	_, err = d2.Derive([]byte("fdsa"))
	assert.Nil(err)
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

	kms1 := testkms.GetKMS(t, secrets[:2], mem.New())
	siger, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms1.Signer()))

	ser, err := vrc.Serialize()
	_, err = siger.Derive(ser)

	msg = &event.Message{
		Event:      vrc,
		Signatures: []derivation.Derivation{*siger},
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
		err := db.LogEvent(evt, true)
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
