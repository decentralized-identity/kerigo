package keri

import (
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
)

type ReplayMode int

const (
	FirstSeenReplay ReplayMode = iota
	SequenceNumberReplay
)

type ReplayHandler func(e *event.Message) error

func (r *Keri) Replay(pre string, mode ReplayMode, handler ReplayHandler) error {
	var streamer func(string, func(e *event.Message) error) error
	switch mode {
	case FirstSeenReplay:
		streamer = r.db.StreamAsFirstSeen
	case SequenceNumberReplay:
		streamer = r.db.StreamBySequenceNo
	default:
		return errors.New("invalid replay type")
	}

	return streamer(pre, handler)
}
