package event

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
	kms2 "github.com/decentralized-identity/kerigo/pkg/test/kms"
)

func TestMessageSerialization(t *testing.T) {
	expectedMsgBytes := `{"v":"KERI10JSON000000_","i":"Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU","s":"0","t":"icp","kt":"1","k":["D69EflciVP9zgsihNU14Dbm2bPXoNGxKHK_BBVFMQ-YU"],"n":"E2N7cav-AXF8R86YPUWqo8oGu2YcdyFz_w6lTiNmmOY4","wt":"0","w":[],"c":[]}-AABAA8UlKZCFEDmeWhk1MhyqwjXVobNEnjdApJ02k2ES3eDTT4jZBo8gZ0rdPRACS11xcCiXBYWLasL0bezI1JyzxBg`
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := kms2.GetKMS(t, secrets)

	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(kms.PublicKey()))
	assert.NoError(t, err)

	keyPre := prefix.New(keyDer)

	nextKeyPre := prefix.New(kms.Next())

	icp, err := NewInceptionEvent(WithPrefix("Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU"), WithKeys(keyPre), WithDefaultVersion(JSON), WithNext(1, derivation.Blake3256, nextKeyPre))
	assert.NoError(t, err)

	d, err := icp.Serialize()
	assert.NoError(t, err)

	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(kms.Signer()))
	assert.NoError(t, err)

	_, err = sig.Derive(d)
	assert.NoError(t, err)

	msg := &Message{
		Event:      icp,
		Signatures: []derivation.Derivation{*sig},
		Seen:       time.Time{},
	}

	b, err := msg.Serialize()
	assert.NoError(t, err)

	assert.Equal(t, string(expectedMsgBytes), string(b))

}
