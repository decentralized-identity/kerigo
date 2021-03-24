package direct

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/decentralized-identity/kerigo/pkg/db/badger"
	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/event"
	"github.com/decentralized-identity/kerigo/pkg/keri"
	"github.com/decentralized-identity/kerigo/pkg/test/kms"
	"github.com/decentralized-identity/kerigo/pkg/test/util"
)

func TestDial(t *testing.T) {
	addr := ":5904"
	bobSecrets := []string{
		"Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
		"A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
	}

	bobKMS := kms.GetKMS(t, bobSecrets, mem.New())

	bobID, err := keri.New(bobKMS, mem.New())
	assert.NoError(t, err)

	cli, err := Dial(bobID, addr)
	assert.Error(t, err)
	assert.Nil(t, cli)

}

func TestSingleMessage(t *testing.T) {
	eveSecrets := []string{
		"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
		"A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
	}
	addr := ":5901"

	eveTD, eveCancel := util.GetTempDir(t)
	defer eveCancel()

	eveDB, err := badger.New(eveTD)
	assert.NoError(t, err)

	eveKMS := kms.GetKMS(t, eveSecrets, eveDB)

	eveID, err := keri.New(eveKMS, eveDB)
	assert.NoError(t, err)

	srv := &Server{
		Addr: addr,
		BaseIdentity: func(l net.Listener) *keri.Keri {
			return eveID
		},
	}

	go func() {
		err = srv.ListenAndServe()
	}()

	bobSecrets := []string{
		"Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
		"A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
		"AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
	}

	bobTD, bobCancel := util.GetTempDir(t)
	defer bobCancel()

	bobDB, err := badger.New(bobTD)
	assert.NoError(t, err)

	bobKMS := kms.GetKMS(t, bobSecrets, bobDB)

	bobID, err := keri.New(bobKMS, bobDB)
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

func xTestWithNotify(t *testing.T) {
	eveSecrets := []string{
		"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
		"A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
	}
	addr := ":5902"

	eveKMS := kms.GetKMS(t, eveSecrets, mem.New())

	eveID, err := keri.New(eveKMS, mem.New())
	assert.NoError(t, err)

	srv := &Server{
		Addr: addr,
		BaseIdentity: func(l net.Listener) *keri.Keri {
			return eveID
		},
	}

	go func() {
		err = srv.ListenAndServe()
	}()

	bobSecrets := []string{
		"Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
		"A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
		"AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
	}

	bobKMS := kms.GetKMS(t, bobSecrets, mem.New())

	bobID, err := keri.New(bobKMS, mem.New())
	assert.NoError(t, err)

	cli, err := DialTimeout(bobID, addr, 5*time.Second)

	msg, err := bobID.Inception()
	assert.NoError(t, err)

	var rcptReceived atomic.Value
	rcptReceived.Store(false)
	err = cli.WriteNotify(msg, func(rcpt *event.Event, err error) {
		rcptReceived.Store(true)
	})
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		_, err := eveID.FindConnection("EQP28yaaIK9NBwG0Xr1kLqJCdsly7TCXEhX4yJdLnC3s")
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	assert.Eventually(t, func() bool {
		_, err := bobID.FindConnection("EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w")
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	assert.Eventually(t, func() bool {
		return rcptReceived.Load().(bool)
	}, 5*time.Second, 50*time.Millisecond)

	assert.Equal(t, "EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w", eveID.Prefix())
	assert.Equal(t, "EQP28yaaIK9NBwG0Xr1kLqJCdsly7TCXEhX4yJdLnC3s", bobID.Prefix())

	err = cli.Close()
	assert.NoError(t, err)

}
