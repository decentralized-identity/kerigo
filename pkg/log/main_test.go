package log

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
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
	inceptionBytes := []byte(`{"v":"KERI10JSON0000cf_","i":"Bh8On2eI1L-5OhKPLgnMh80ovcP8sV6E7Lcg3FDy-TbI","s":"0","t":"icp","kt":"1","k":["Bh8On2eI1L-5OhKPLgnMh80ovcP8sV6E7Lcg3FDy-TbI"],"n":"","wt":"0","w":[],"c":[]}`)
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

	incept := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}`)
	inceptSig := []byte(`-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

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

	rot := []byte(`{"v":"KERI10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}`)
	rotSig := []byte(`-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

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

	ixn := []byte(`{"v":"KERI10JSON000098_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"2","t":"ixn","p":"ELWbb2Oun3FTpWZqHYmeefM5B-11nZQBsxPfufyjJHy4","a":[]}`)
	ixnSig := []byte(`-AABAAqxzoxk4rltuP41tB8wEpHFC4Yd1TzhOGfuhlylbDFAm73jB2emdvaLjUP6FrHxiPqS2CcbAWaVNsmii80KJEBw`)

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
}
