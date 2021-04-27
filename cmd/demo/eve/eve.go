package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	kbdgr "github.com/decentralized-identity/kerigo/pkg/db/badger"
	"github.com/decentralized-identity/kerigo/pkg/direct"
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
	e := flag.Int("e", 60, "Expire time for demo. Default is 60.0.")
	flag.Parse()

	td, err := ioutil.TempDir("", "keri-*")
	if err != nil {
		panic(err)
	}
	defer removeTempDir(td)

	db, err := kbdgr.New(td)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		panic(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		panic(err)
	}

	km, err = keymanager.NewKeyManager(keymanager.WithAEAD(a), keymanager.WithStore(db), keymanager.WithSecrets(secrets))
	if err != nil {
		panic(err)
	}

	kerl, err := keri.New(km, db)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Direct Mode demo of Eve as %s on TCP port 5621 to port 5620\n\n\n", kerl.Prefix())

	srv := &direct.Server{
		Addr: ":5621",
		BaseIdentity: func(l net.Listener) *keri.Keri {
			return kerl
		},
	}

	go func(t int) {
		select {
		case <-time.After(time.Duration(t) * time.Second):
			os.Exit(0)
		}
	}(*e)

	err = srv.ListenAndServe()
	log.Printf("direct mode server exited with %v\n", err)
}

func removeTempDir(td string) {
	err := os.RemoveAll(td)
	if err != nil {
		fmt.Println(err)
	}
}
