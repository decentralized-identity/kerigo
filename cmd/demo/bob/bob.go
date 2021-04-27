package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	kbdgr "github.com/decentralized-identity/kerigo/pkg/db/badger"
	"github.com/decentralized-identity/kerigo/pkg/direct"
	"github.com/decentralized-identity/kerigo/pkg/event"
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
	e := flag.Int("e", 60, "Expire time for demo. Default is 60.0.")
	flag.Parse()

	td, err := ioutil.TempDir("", "keri-bob-*")
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

	fmt.Printf("Direct Mode demo of Bob as %s on TCP port 5620 to port 5621\n\n\n", kerl.Prefix())

	cli, err := direct.DialTimeout(kerl, ":5621", time.Duration(*e)*time.Second)
	if err != nil {
		panic(err)
	}

	msg, err := kerl.Inception()
	if err != nil {
		panic(err)
	}

	err = cli.WriteNotify(msg, func(rcpt *event.Event, err error) {
		if err != nil {
			panic(err)
		}

		rot, err := kerl.Rotate()
		if err != nil {
			panic(err)
		}

		err = cli.WriteNotify(rot, func(rcpt *event.Event, err error) {
			if err != nil {
				panic(err)
			}

			ixn, err := kerl.Interaction([]*event.Seal{})
			if err != nil {
				panic(err)
			}

			err = cli.Write(ixn)
			if err != nil {
				panic(err)
			}

		})
		if err != nil {
			panic(err)
		}
	})

	select {
	case <-time.After(time.Duration(*e) * time.Second):
		os.Exit(0)
	}
}

func removeTempDir(td string) {
	err := os.RemoveAll(td)
	if err != nil {
		fmt.Println(err)
	}
}
