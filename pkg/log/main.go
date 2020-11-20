package log

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

type Log struct {
	Events   []*event.Event
	Escrowed []*event.Event
}

// BySequence implements the sort.Inteface for log events
type BySequence []*event.Event

func (a BySequence) Len() int      { return len(a) }
func (a BySequence) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BySequence) Less(i, j int) bool {
	iS, _ := strconv.ParseInt(a[i].Sequence, 16, 64)
	jS, _ := strconv.ParseInt(a[j].Sequence, 16, 64)
	return iS < jS
}

// Inception returns the inception event for this log
func (l *Log) Inception() *event.Event {
	for _, e := range l.Events {
		if e.EventType == event.ICP.String() {
			return e
		}
	}
	return nil
}

// Current return the current event in the log
func (l *Log) Current() *event.Event {
	sort.Sort(BySequence(l.Events))
	return l.Events[len(l.Events)-1]
}

// Apply the provided event to the log
// This function will confirm the sequence number and digest
// for the new log are correct before applying
func (l *Log) Apply(e *event.Event) error {
	if len(l.Events) == 0 {
		if e.EventType != event.ICP.String() {
			return errors.New("first event in an empty log must be an inception event")
		}
		l.Events = append(l.Events, e)
		return nil
	}

	current := l.Current()
	if e.SequenceInt() != current.SequenceInt()+1 {
		return errors.New("invalid sequence for new event")
	}

	incomingDerivation, err := derivation.FromPrefix(e.Digest)
	if err != nil {
		return fmt.Errorf("unable to determin digest derivation (%s)", err)
	}

	cSerialized, err := current.Serialize()
	if err != nil {
		return fmt.Errorf("unable to serialize current event (%s)", err)
	}

	currentDigest, err := event.Digest(cSerialized, incomingDerivation.Code)
	if err != nil {
		return fmt.Errorf("unable to digest current event (%s)", err)
	}

	if !bytes.Equal(currentDigest, incomingDerivation.Raw) {
		return errors.New("invalid digest for new event")
	}

	l.Events = append(l.Events, e)

	return nil
}
