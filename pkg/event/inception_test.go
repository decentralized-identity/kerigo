package event

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/test"
)

func TestIncept(t *testing.T) {
	secrets := []string{"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s", "AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc"}
	kms := test.GetKMS(t, secrets)

	icp, err := Incept(kms.PublicKey(), kms.Next())
	assert.NoError(t, err)

	assert.Equal(t, "Eh0fefvTQ55Jwps4dVnIekf7mZgWoU8bCUsDsKeGiEgU", icp.Prefix)
	assert.Equal(t, "D69EflciVP9zgsihNU14Dbm2bPXoNGxKHK_BBVFMQ-YU", icp.Keys[0])
	assert.Equal(t, "E2N7cav-AXF8R86YPUWqo8oGu2YcdyFz_w6lTiNmmOY4", icp.Next)
}
