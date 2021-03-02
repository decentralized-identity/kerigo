package badger

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	testkms "github.com/decentralized-identity/kerigo/pkg/test/kms"
)

var (
	secrets = []string{
		"AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw",
		"AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ",
	}
)

func TestPut(t *testing.T) {

	t.Run("empty get", func(t *testing.T) {
		td, cleanup := getTempDir(t)
		defer cleanup()

		db, err := New(td)
		assert.NoError(t, err)

		v, err := db.Get("test")
		assert.Empty(t, v)
		assert.NotNil(t, err)
		assert.Equal(t, "error getting from badger: Key not found", err.Error())
	})

	t.Run("put and get", func(t *testing.T) {
		td, cleanup := getTempDir(t)
		defer cleanup()

		db, err := New(td)
		assert.NoError(t, err)

		err = db.Put("test", []byte("value"))

		v, err := db.Get("test")

		assert.NoError(t, err)
		assert.Equal(t, []byte("value"), v)
	})
}

func TestLogEvent(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	msg := &event.Message{Event: evt}
	err = db.LogEvent(msg, true)
	assert.NoError(t, err)

	assert.Equal(t, 1, db.LogSize("pre"))
	icp, err := db.Inception("pre")
	assert.NoError(t, err)

	expectedDig, err := evt.GetDigest()
	assert.NoError(t, err)
	actualDig, err := icp.Event.GetDigest()
	assert.NoError(t, err)

	assert.EqualValues(t, expectedDig, actualDig)
}

func TestLogSize(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 12; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt}, true)
		require.NoError(t, err)
	}

	assert.Equal(t, db.LogSize("pre"), 12)

}

func TestStreamLog(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt}, false)
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 12; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt}, true)
		require.NoError(t, err)
	}

	count := 0
	err = db.StreamAsFirstSeen("pre", func(msg *event.Message) error {
		count++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 12, count)

	err = db.StreamAsFirstSeen("pre", func(msg *event.Message) error {
		return errors.New("boom")
	})

	assert.Error(t, err)
}

func TestStreamEstablisment(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 4; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt}, true)
		require.NoError(t, err)
	}

	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "4",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}
	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	count := 0
	err = db.StreamEstablisment("pre", func(msg *event.Message) error {
		count++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	err = db.StreamEstablisment("pre", func(msg *event.Message) error {
		return errors.New("boom")
	})

	assert.Error(t, err)

}

func TestStreamSequenceNo(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 4; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt}, true)
		require.NoError(t, err)
	}

	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "2",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}
	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	count := 0
	var last *event.Message
	err = db.StreamBySequenceNo("pre", func(msg *event.Message) error {
		count++
		last = msg
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.Equal(t, "rot", last.Event.EventType)

	err = db.StreamBySequenceNo("pre", func(msg *event.Message) error {
		return errors.New("boom")
	})

	assert.Error(t, err)
}

func TestPending(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.EscrowPendingEvent(&event.Message{Event: evt})
	assert.NoError(t, err)

	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.EscrowPendingEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	count := 0
	err = db.StreamPending("pre", func(e *event.Message) error {
		count++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, count)

	err = db.StreamPending("pre", func(e *event.Message) error {
		return errors.New("boom")
	})

	assert.Error(t, err)

}

func TestSeen(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	assert.NoError(t, err)

	ok := db.Seen("pre")
	assert.True(t, ok)

	ok = db.Seen("not-pre")
	assert.False(t, ok)
}

func TestInception(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	orig := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: orig}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "2",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}
	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	icp, err := db.Inception("pre")
	assert.NoError(t, err)

	expectedDig, err := orig.GetDigest()
	assert.NoError(t, err)
	actualDig, err := icp.Event.GetDigest()
	assert.NoError(t, err)

	assert.EqualValues(t, expectedDig, actualDig)
}

func TestCurrentEvent(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	orig := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: orig}, true)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	rot := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "1",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: rot}, true)
	require.NoError(t, err)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}
	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	cur, err := db.CurrentEvent("pre")
	assert.NoError(t, err)

	expectedDig, err := evt.GetDigest()
	assert.NoError(t, err)
	actualDig, err := cur.Event.GetDigest()
	assert.NoError(t, err)

	assert.EqualValues(t, expectedDig, actualDig)
}

func TestCurrentEstablishmentEvent(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	orig := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: orig}, true)
	assert.NoError(t, err)
	assert.Equal(t, db.LogSize("pre"), 1)

	rot := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "1",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: rot}, true)
	require.NoError(t, err)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}
	err = db.LogEvent(&event.Message{Event: evt}, true)
	require.NoError(t, err)

	cur, err := db.CurrentEstablishmentEvent("pre")
	assert.NoError(t, err)

	expectedDig, err := rot.GetDigest()
	assert.NoError(t, err)
	actualDig, err := cur.Event.GetDigest()
	assert.NoError(t, err)

	assert.EqualValues(t, expectedDig, actualDig)
}

func TestEventAt(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	icp := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: icp}, true)
	assert.NoError(t, err)

	rot := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "rot",
		Sequence:  "1",
		Keys:      []string{"k2.1", "k2.2", "k2.3"},
		Next:      "next2",
		Witnesses: []string{"w1"},
	}

	err = db.LogEvent(&event.Message{Event: rot}, true)
	require.NoError(t, err)

	ixn := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}

	err = db.LogEvent(&event.Message{Event: ixn}, true)
	require.NoError(t, err)

	at, err := db.EventAt("pre", 0)
	assert.NoError(t, err)

	expectedDig, err := icp.GetDigest()
	assert.NoError(t, err)
	actualDig, err := at.Event.GetDigest()
	assert.NoError(t, err)

	assert.EqualValues(t, expectedDig, actualDig)

	at, err = db.EventAt("pre", 1)
	assert.NoError(t, err)

	expectedDig, err = rot.GetDigest()
	assert.NoError(t, err)
	actualDig, err = at.Event.GetDigest()
	assert.NoError(t, err)

	at, err = db.EventAt("pre", 2)
	assert.NoError(t, err)

	expectedDig, err = ixn.GetDigest()
	assert.NoError(t, err)
	actualDig, err = at.Event.GetDigest()
	assert.NoError(t, err)
}

func TestSignatures(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	icp := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	dig, err := icp.GetDigest()
	assert.NoError(t, err)

	kms := testkms.GetKMS(t, secrets)

	ser, err := icp.Serialize()
	assert.NoError(t, err)

	der, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms.Signer()))
	assert.NoError(t, err)

	_, err = der.Derive(ser)

	err = db.LogEvent(&event.Message{Event: icp, Signatures: []derivation.Derivation{*der}}, true)
	assert.NoError(t, err)

	sigs, err := db.Signatures("pre", dig)
	assert.NoError(t, err)

	assert.Len(t, sigs, 1)
	assert.Equal(t, sigs[0].AsPrefix(), der.AsPrefix())
}

func TestEvent(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	icp := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	dig, err := icp.GetDigest()
	assert.NoError(t, err)

	err = db.LogEvent(&event.Message{Event: icp}, true)
	assert.NoError(t, err)

	ret, err := db.Event("pre", dig)
	assert.NoError(t, err)

	rdig, err := ret.GetDigest()
	assert.NoError(t, err)

	assert.Equal(t, dig, rdig)
}

func TestMessage(t *testing.T) {
	td, cleanup := getTempDir(t)
	defer cleanup()

	db, err := New(td)
	assert.NoError(t, err)
	assert.NotNil(t, db)

	icp := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "icp",
		Sequence:  "0",
		Keys:      []string{"k1.1", "k1.2", "k1.3"},
		Next:      "next1",
		Witnesses: []string{"w1"},
	}

	dig, err := icp.GetDigest()
	assert.NoError(t, err)

	kms := testkms.GetKMS(t, secrets)

	ser, err := icp.Serialize()
	assert.NoError(t, err)

	der, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms.Signer()))
	assert.NoError(t, err)

	_, err = der.Derive(ser)

	err = db.LogEvent(&event.Message{Event: icp, Signatures: []derivation.Derivation{*der}}, true)
	assert.NoError(t, err)

	msg, err := db.Message("pre", dig)
	assert.NoError(t, err)

	rdig, err := msg.Event.GetDigest()
	assert.NoError(t, err)

	assert.Equal(t, dig, rdig)

	sigs := msg.Signatures
	assert.Len(t, sigs, 1)
	assert.Equal(t, sigs[0].AsPrefix(), der.AsPrefix())
}

func getTempDir(t *testing.T) (string, func()) {
	td, err := ioutil.TempDir("", "badger-test-*")
	require.NoError(t, err)

	cleanup := func() {
		err := os.RemoveAll(td)
		require.NoError(t, err)
	}

	return td, cleanup
}
