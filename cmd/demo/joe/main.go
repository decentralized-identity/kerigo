package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"

	kbdgr "github.com/decentralized-identity/kerigo/pkg/db/badger"
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
)

func main() {

	goodGuy := createGoodGuy()
	badGuy := createBadGuy()
	innocent := createInnocent()

	count := 0
	err := goodGuy.Replay(goodGuy.Prefix(), keri.FirstSeenReplay, func(e *event.Message) error {
		err := innocent.ProcessEvent(e)
		count++
		return err
	})
	fmt.Printf("Good Guy replayed first %d events\n", count)

	if err != nil {
		log.Fatalf("innocent error processing good guy %v\n", err)
	}

	//IXN
	ixn, err := badGuy.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	dig, _ := ixn.Event.GetDigest()
	fmt.Println("Bad Guy duplicitious IXN", dig)
	err = innocent.ProcessEvent(ixn)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	//IXN
	ixn, err = badGuy.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	dig, _ = ixn.Event.GetDigest()
	fmt.Println("Bad Guy 2nd duplicitious IXN", dig)
	err = innocent.ProcessEvent(ixn)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	//IXN
	ixn, err = badGuy.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	dig, _ = ixn.Event.GetDigest()
	fmt.Println("Bad Guy 3rd duplicitious IXN", dig)
	err = innocent.ProcessEvent(ixn)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	rot, err := goodGuy.Rotate()
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	dig, _ = rot.Event.GetDigest()
	fmt.Println("Good Guy recover ROT", dig)
	err = innocent.ProcessEvent(rot)
	if err != nil {
		log.Fatalf("%+v\n", err)
	}

	fmt.Println("****************************************************")
	fmt.Println("*************** First Seen Replay ******************")
	fmt.Println("****************************************************")
	err = innocent.Replay(goodGuy.Prefix(), keri.FirstSeenReplay, func(e *event.Message) error {
		dig, _ := e.Event.GetDigest()
		fmt.Println(e.Event.EventType, e.Event.Sequence, "-", dig)
		return nil
	})
	fmt.Println("****************************************************")
	fmt.Println("")

	fmt.Println("****************************************************")
	fmt.Println("***************** Seq No Replay ********************")
	fmt.Println("****************************************************")
	err = innocent.Replay(goodGuy.Prefix(), keri.SequenceNumberReplay, func(e *event.Message) error {
		dig, _ := e.Event.GetDigest()
		fmt.Println(e.Event.EventType, e.Event.Sequence, "-", dig)
		return nil
	})
	fmt.Println("****************************************************")
	fmt.Println("")

	if err != nil {
		log.Fatalf("%+v\n", err)
	}
}

func createInnocent() *keri.Keri {
	td, err := ioutil.TempDir("", "keri-innocent-*")
	if err != nil {
		log.Fatalln(err)
	}

	db, err := kbdgr.New(td)
	if err != nil {
		log.Fatalln(err)
	}
	//
	//db := mem.New()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatalln(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatalln(err)
	}

	km, err := keymanager.NewKeyManager(keymanager.WithAEAD(a), keymanager.WithStore(db))
	if err != nil {
		log.Fatalln(err)
	}

	//ICP
	kerl, err := keri.New(km, db)
	if err != nil {
		log.Fatalln(err)
	}

	return kerl
}

func createGoodGuy() *keri.Keri {
	td, err := ioutil.TempDir("", "keri-good-*")
	if err != nil {
		log.Fatalln(err)
	}

	db, err := kbdgr.New(td)
	if err != nil {
		log.Fatalln(err)
	}
	//
	//db := mem.New()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatalln(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatalln(err)
	}

	km, err := keymanager.NewKeyManager(keymanager.WithAEAD(a), keymanager.WithStore(db), keymanager.WithSecrets(secrets))
	if err != nil {
		log.Fatalln(err)
	}

	//ICP
	kerl, err := keri.New(km, db)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Good Guy Prefix:", kerl.Prefix())

	//ROT
	_, err = kerl.Rotate()
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	//ROT
	_, err = kerl.Rotate()
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	return kerl

}

func createBadGuy() *keri.Keri {
	td, err := ioutil.TempDir("", "keri-bad-*")
	if err != nil {
		log.Fatalln(err)
	}

	db, err := kbdgr.New(td)
	if err != nil {
		log.Fatalln(err)
	}
	//
	//db := mem.New()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatalln(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatalln(err)
	}

	km, err := keymanager.NewKeyManager(keymanager.WithAEAD(a), keymanager.WithStore(db), keymanager.WithSecrets(secrets))
	if err != nil {
		log.Fatalln(err)
	}

	//ICP
	kerl, err := keri.New(km, db)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Bad Guy Prefix:", kerl.Prefix())

	//ROT
	_, err = kerl.Rotate()
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	//ROT
	_, err = kerl.Rotate()
	if err != nil {
		log.Fatalln(err)
	}

	//IXN
	_, err = kerl.Interaction([]*event.Seal{})
	if err != nil {
		log.Fatalln(err)
	}

	return kerl
}
