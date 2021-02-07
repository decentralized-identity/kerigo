package direct

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/keri"
	"github.com/decentralized-identity/kerigo/pkg/test"
)

func TestSingleMessage(t *testing.T) {
	eveSecrets := []string{
		"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
		"A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
	}
	addr := ":5901"

	eveKMS := test.GetKMS(t, eveSecrets)

	eveID, err := keri.New(eveKMS)
	assert.NoError(t, err)

	srv := &Server{
		Addr: addr,
		BaseIdentity: func(l net.Listener) *keri.Keri {
			return eveID
		},
	}

	go func() {
		err = srv.ListenAndServer()
	}()

	bobSecrets := []string{
		"Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
		"A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
		"AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
	}

	bobKMS := test.GetKMS(t, bobSecrets)

	bobID, err := keri.New(bobKMS)
	assert.NoError(t, err)

	cli, err := DialTimeout(bobID, addr, 5*time.Second)

	msg, err := bobID.Inception()
	assert.NoError(t, err)

	err = cli.Write(msg)
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		_, err := eveID.FindConnection("EQP28yaaIK9NBwG0Xr1kLqJCdsly7TCXEhX4yJdLnC3s")
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	assert.Eventually(t, func() bool {
		_, err := bobID.FindConnection("EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w")
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, "EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w", eveID.Prefix())
	assert.Equal(t, "EQP28yaaIK9NBwG0Xr1kLqJCdsly7TCXEhX4yJdLnC3s", bobID.Prefix())

	err = cli.Close()
	assert.NoError(t, err)

}
