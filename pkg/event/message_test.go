package event

import (
	"crypto/ed25519"
	"testing"

	"github.com/google/tink/go/signature/subtle"
	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/prefix"
)

func TestMessageSerialization(t *testing.T) {
	expectedMsgBytes := `{"v":"KERI10JSON000000_","i":"Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU","s":"0","t":"icp","kt":"1","k":["D69EflciVP9zgsihNU14Dbm2bPXoNGxKHK_BBVFMQ-YU"],"n":"E2N7cav-AXF8R86YPUWqo8oGu2YcdyFz_w6lTiNmmOY4","wt":"0","w":[],"c":[]}-AABAA8UlKZCFEDmeWhk1MhyqwjXVobNEnjdApJ02k2ES3eDTT4jZBo8gZ0rdPRACS11xcCiXBYWLasL0bezI1JyzxBg`

	der, err := derivation.FromPrefix("ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s")
	assert.NoError(t, err)

	edPriv := ed25519.NewKeyFromSeed(der.Raw)
	edPub := edPriv.Public()
	signer, err := subtle.NewED25519SignerFromPrivateKey(&edPriv)

	keyDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(edPub.(ed25519.PublicKey)))
	assert.NoError(t, err)
	keyPre := prefix.New(keyDer)

	der, err = derivation.FromPrefix("AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc")
	assert.NoError(t, err)

	nextPriv := ed25519.NewKeyFromSeed(der.Raw)
	nextPub := nextPriv.Public()

	nextDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(nextPub.(ed25519.PublicKey)))
	assert.NoError(t, err)
	nextKeyPre := prefix.New(nextDer)

	icp, err := NewInceptionEvent(
		WithPrefix("Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU"),
		WithKeys(keyPre),
		WithDefaultVersion(JSON),
		WithNext("1", derivation.Blake3256, nextKeyPre))
	assert.NoError(t, err)

	d, err := icp.Serialize()
	assert.NoError(t, err)

	sig, err := derivation.New(derivation.WithCode(derivation.Ed25519Attached), derivation.WithSigner(signer.Sign))
	assert.NoError(t, err)

	_, err = sig.Derive(d)
	assert.NoError(t, err)

	msg := &Message{
		Event:      icp,
		Signatures: []derivation.Derivation{*sig},
	}

	b, err := msg.Serialize()
	assert.NoError(t, err)

	assert.Equal(t, expectedMsgBytes, string(b))

}
