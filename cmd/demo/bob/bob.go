package main

import (
	"fmt"
	"time"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/io/stream"
	"github.com/decentralized-identity/kerigo/pkg/keri"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

var (
	secrets = []string{
		"ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc",
		"A6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q",
		"AcwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y",
		"Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8",
		"A1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E",
		"AKuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc",
		"AxFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw",
		"ALq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY",
	}
	km *keymanager.KeyManager
)

func main() {
	store := mem.NewMemDB()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		panic(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		panic(err)
	}

	km, err = keymanager.NewKeyManager(a, store, keymanager.WithSecrets(secrets))
	if err != nil {
		panic(err)
	}

	kerl, err := keri.New(km)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Direct Mode demo of Bob as %s on TCP port 5620 to port 5621\n\n\n", kerl.Prefix())

	outb, err := stream.NewStreamOutbound(":5621", 60*time.Second)
	if err != nil {
		panic(err)
	}

	msg, err := kerl.Inception()
	if err != nil {
		panic(err)
	}

	err = outb.Write(msg)
	if err != nil {
		panic(err)
	}

	err = kerl.HandleDirect(outb)
	if err != nil {
		panic(err)
	}

	ch := make(chan bool)
	<-ch
}
