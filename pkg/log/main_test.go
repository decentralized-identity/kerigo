package log

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	"github.com/stretchr/testify/assert"
)

func TestOrder(t *testing.T) {
	assert := assert.New(t)
	l := Log{}

	icp, err := event.NewEvent(event.WithType(event.ICP))
	assert.Nil(err)

	l.Events = append(l.Events, icp)

	e, err := event.NewEvent(event.WithType(event.ROT), event.WithSequence(1))
	assert.Nil(err)

	l.Events = append(l.Events, e)

	e, err = event.NewEvent(event.WithType(event.ROT), event.WithSequence(2))
	assert.Nil(err)

	l.Events = append(l.Events, e)

	latest, err := event.NewEvent(event.WithType(event.ROT), event.WithSequence(3))
	assert.Nil(err)

	l.Events = append(l.Events, latest)

	e = l.Inception()
	assert.Same(icp, e)

	e = l.Current()
	assert.Same(latest, e)
}

func TestApply(t *testing.T) {
	assert := assert.New(t)

	// Pre-defined inception json
	inceptionBytes := []byte(`{"vs":"KERI10JSON0000cf_","pre":"Bh8On2eI1L-5OhKPLgnMh80ovcP8sV6E7Lcg3FDy-TbI","sn":"0","ilk":"icp","sith":"1","keys":["Bh8On2eI1L-5OhKPLgnMh80ovcP8sV6E7Lcg3FDy-TbI"],"nxt":"","toad":"0","wits":[],"cnfg":[]}`)
	icp := &event.Event{}
	err := json.Unmarshal(inceptionBytes, icp)
	assert.Nil(err)

	// pre-defined inception basic non-transferrable key
	basicDerivation, err := derivation.FromPrefix("BNAuSRPM2aAwVqsrq97N58khKE6VPTusEOncafpFk9O4")
	assert.Nil(err)
	basicPre := prefix.New(basicDerivation)

	// correct digest prefix
	digestPre := "Etq3upkY_KoTFc0dJaZ_QRmU1Eb5-kEpcqHoGhzeSCk0"

	// New log
	l := Log{Events: []*event.Event{icp}}

	nextEvent, err := event.NewEvent(
		event.WithKeys(basicPre),
		event.WithSequence(1),
		event.WithDigest(digestPre),
		event.WithType(event.IXN),
		event.WithDefaultVersion(event.JSON),
	)
	assert.Nil(err)

	// Wrong Sequence
	nextEvent.Sequence = fmt.Sprintf("%x", 12352)

	err = l.Apply(nextEvent)
	if assert.NotNil(err) {
		assert.Equal("invalid sequence for new event", err.Error())
	}

	// Set correct sequence
	nextEvent.Sequence = fmt.Sprintf("%x", 1)

	// Wrong Digest
	nextEvent.Digest = "nope!"

	err = l.Apply(nextEvent)
	if assert.NotNil(err) {
		assert.Equal("unable to determin digest derivation (unable to determin derevation from code n)", err.Error())
	}

	nextEvent.Digest = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	err = l.Apply(nextEvent)
	if assert.NotNil(err) {
		assert.Equal("invalid digest for new event", err.Error())
	}
}
