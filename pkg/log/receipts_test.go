package log

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

func TestAddReceipt(t *testing.T) {
	k, err := newKeys(2)
	assert.NoError(t, err)

	icp, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(k[0].pre))
	assert.NoError(t, err)
	est, err := event.NewInceptionEvent(event.WithDefaultVersion(event.JSON), event.WithKeys(k[1].pre))
	assert.NoError(t, err)

	vrc, err := event.TransferableReceipt(icp, est, derivation.Blake3256)
	assert.NoError(t, err)

	msg := &event.Message{
		Event: vrc,
	}

	r := Register{}
	err = r.Add(msg)
	assert.NoError(t, err)

	dig := vrc.Digest

	rcpt := r[dig]
	assert.Len(t, rcpt, 1)
	assert.Equal(t, msg, rcpt[0])

}
