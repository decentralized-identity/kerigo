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

func TestVerify(t *testing.T) {
	assert := assert.New(t)

	// play the events generated from the keripy implementation
	// TODO: move these to approved test vectors in main keri repo

	l := Log{}

	incept := []byte(`{"vs":"KERI10JSON0000fb_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4","toad":"0","wits":[],"cnfg":[]}`)
	inceptSig := []byte(`-AABAAtf0OqrkGmK3vdMcS5E3mLxeFh14SbvCNjZnZrxAazgYTemZc1S-Pr0ge9IQuHesmh8cJncRkef1PgxFavDKqDQ`)

	msg := &event.Message{Event: &event.Event{}}
	err := json.Unmarshal(incept, msg.Event)
	assert.Nil(err)

	sigs, extra, err := derivation.ParseAttachedSignatures(inceptSig)
	assert.Empty(extra)
	assert.Nil(err)
	assert.Len(sigs, 1)

	msg.Signatures = sigs

	err = l.Verify(msg)
	assert.Nil(err)

	err = l.Apply(msg.Event)
	assert.Nil(err)

	ixn := []byte(`{"vs":"KERI10JSON0000a3_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"1","ilk":"ixn","dig":"EixO2SBNow3tYDfYX6NRt1O9ZSMx2IsBeWkh8YJRp5VI","data":[]}`)
	ixnSig := []byte(`-AABAAaptFFViQVJs2Rj0zuoOId1qy0B0piJmN7uxxD4N1wJapWXdxSZq-Z3Le6XmbPaMGf7xdfrh7IHi15h-9b7mKBQ`)

	msg = &event.Message{Event: &event.Event{}}
	err = json.Unmarshal(ixn, msg.Event)
	assert.Nil(err)

	sigs, extra, err = derivation.ParseAttachedSignatures(ixnSig)
	assert.Empty(extra)
	assert.Nil(err)
	assert.Len(sigs, 1)

	err = l.Verify(msg)
	assert.Nil(err)

	err = l.Apply(msg.Event)
	assert.Nil(err)

	rot := []byte(`{"vs":"KERI10JSON00013a_","pre":"ETT9n-TCGn8XfkGkcNeNmZgdZSwHPLyDsojFXotBXdSo","sn":"2","ilk":"rot","dig":"EOphiyHf3RGC_gP0_lj402J7-4ux6UpKvDnX8sssu2pc","sith":"1","keys":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"nxt":"EoWDoTGQZ6lJ19LsaV4g42k5gccsB_-ttYHOft6kuYZk","toad":"0","cuts":[],"adds":[],"data":[]}`)
	rotSig := []byte(`-AABAAtuSAbqbOMXTnphZx_c1mH875OO8cQi6zeeTXgDz2LSsnJeOJI2Ov7BF6Sq7YuAXYfkWIOWGdHuFzAFAcx0udBw`)

	msg = &event.Message{Event: &event.Event{}}
	err = json.Unmarshal(rot, msg.Event)
	assert.Nil(err)

	sigs, extra, err = derivation.ParseAttachedSignatures(rotSig)
	assert.Empty(extra)
	assert.Nil(err)
	assert.Len(sigs, 1)

	err = l.Verify(msg)
	assert.Nil(err)

	err = l.Apply(msg.Event)
	assert.Nil(err)
}
