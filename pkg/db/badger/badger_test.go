package badger

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/decentralized-identity/kerigo/pkg/event"
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
	err = db.LogEvent(msg)
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	icp, err := db.Inception("pre")
	assert.NoError(t, err)
	assert.EqualValues(t, evt, icp.Event)
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

	err = db.LogEvent(&event.Message{Event: evt})
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 12; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt})
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

	err = db.LogEvent(&event.Message{Event: evt})
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 12; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt})
		require.NoError(t, err)
	}

	count := 0
	err = db.StreamLog("pre", func(msg *event.Message) {
		count++
	})

	assert.NoError(t, err)
	assert.Equal(t, 12, count)
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

	err = db.LogEvent(&event.Message{Event: evt})
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt = &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 2)

	for i := 2; i < 4; i++ {
		evt.Sequence = fmt.Sprintf("%x", i)

		err = db.LogEvent(&event.Message{Event: evt})
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
	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	count := 0
	err = db.StreamEstablisment("pre", func(msg *event.Message) {
		count++
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, count)

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

	err = db.LogEvent(&event.Message{Event: evt})
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

	err = db.LogEvent(&event.Message{Event: orig})
	assert.NoError(t, err)

	assert.Equal(t, db.LogSize("pre"), 1)
	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "1",
	}

	err = db.LogEvent(&event.Message{Event: evt})
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
	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	icp, err := db.Inception("pre")
	assert.NoError(t, err)
	assert.Equal(t, orig, icp.Event)
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

	err = db.LogEvent(&event.Message{Event: orig})
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

	err = db.LogEvent(&event.Message{Event: rot})
	require.NoError(t, err)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}
	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	cur, err := db.CurrentEvent("pre")
	assert.NoError(t, err)
	assert.Equal(t, evt, cur.Event)
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

	err = db.LogEvent(&event.Message{Event: orig})
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

	err = db.LogEvent(&event.Message{Event: rot})
	require.NoError(t, err)

	evt := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}
	err = db.LogEvent(&event.Message{Event: evt})
	require.NoError(t, err)

	cur, err := db.CurrentEstablishmentEvent("pre")
	assert.NoError(t, err)
	assert.Equal(t, rot, cur.Event)
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

	err = db.LogEvent(&event.Message{Event: icp})
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

	err = db.LogEvent(&event.Message{Event: rot})
	require.NoError(t, err)

	ixn := &event.Event{
		Prefix:    "pre",
		Version:   event.DefaultVersionString(event.JSON),
		EventType: "ixn",
		Sequence:  "2",
	}

	err = db.LogEvent(&event.Message{Event: ixn})
	require.NoError(t, err)

	at, err := db.EventAt("pre", 0)
	assert.NoError(t, err)
	assert.Equal(t, icp, at.Event)

	at, err = db.EventAt("pre", 1)
	assert.NoError(t, err)
	assert.Equal(t, rot, at.Event)

	at, err = db.EventAt("pre", 2)
	assert.NoError(t, err)
	assert.Equal(t, ixn, at.Event)

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
