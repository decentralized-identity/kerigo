package main

import (
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	"github.com/decentralized-identity/kerigo/pkg/db/mem"
	"github.com/decentralized-identity/kerigo/pkg/io/stream"
	"github.com/decentralized-identity/kerigo/pkg/keri"
	"github.com/decentralized-identity/kerigo/pkg/keymanager"
)

var (
	secrets = []string{
		"AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw",
		"AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ",
		"AK-nVhMMJciMPvmF5VZE_9H-nhrgng9aJWf7_UHPtRNM",
		"AT2cx-P5YUjIw_SLCHQ0pqoBWGk9s4N1brD-4pD_ANbs",
		"Ap5waegfnuP6ezC18w7jQiPyQwYYsp9Yv9rYMlKAYL8k",
		"Aqlc_FWWrxpxCo7R12uIz_Y2pHUH2prHx1kjghPa8jT8",
		"AagumsL8FeGES7tYcnr_5oN6qcwJzZfLKxoniKUpG4qc",
		"ADW3o9m3udwEf0aoOdZLLJdf1aylokP0lwwI_M2J9h0s",
	}
	km *keymanager.KeyManager
)

func main() {

	inb, err := stream.NewStreamInbound(":5621")
	if err != nil {
		panic(err)
	}

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

	fmt.Printf("Direct Mode demo of Eve as %s on TCP port 5621 to port 5620\n\n\n", kerl.Prefix())

	err = kerl.HandleInboundDirect(inb)
	if err != nil {
		panic(err)
	}

	ch := make(chan bool)
	<-ch

}
