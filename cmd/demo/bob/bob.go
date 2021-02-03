package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/signature/subtle"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

func main() {
	//client, err := net.Dial("tcp", ":5621")
	//if err != nil {
	//	panic(err)
	//}
	//
	//ticker := time.Tick(3 * time.Second)
	//
	//written := 0
	//for range ticker {
	//	c, err := client.Write([]byte(`{"v":"KERI10JSON0000e6_" "i": "asdfasdfasdfsaf"`))
	//	if err != nil {
	//		panic(err)
	//	}
	//	written += c
	//	fmt.Printf("wrote %d so far\n", written)
	//}

	handle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)

	err = insecurecleartextkeyset.Write(handle, w)
	if err != nil {
		panic(err)
	}

	//fmt.Println(string(buf.Bytes()))

	der, err := derivation.FromPrefix("AgjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw")
	if err != nil {
		panic(err)
	}
	privkey := ed25519.NewKeyFromSeed(der.Raw)

	oldsig, _ := subtle.NewED25519SignerFromPrivateKey(&privkey)
	oldb, err := oldsig.Sign([]byte("I<3keri"))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(oldb))

	b, err := NewKeyHandle(der.Raw)
	if err != nil {
		panic(err)
	}

	keyJson := `{"primaryKeyId":1093351049,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.Ed25519PrivateKey","value":"%s","keyMaterialType":"ASYMMETRIC_PRIVATE"},"status":"ENABLED","keyId":1093351049,"outputPrefixType":"RAW"}]}`

	newKeyJs := fmt.Sprintf(keyJson, b)

	r := keyset.NewJSONReader(bytes.NewBuffer([]byte(newKeyJs)))
	newh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		panic(err)
	}

	sig, _ := signature.NewSigner(newh)
	newb, err := sig.Sign([]byte("I<3keri"))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(newb))

	//pubKH, err := newh.Public()
	//if err != nil {
	//	panic(err)
	//}
	//buf = new(bytes.Buffer)
	//pubKeyWriter := keyset.NewJSONWriter(buf)
	//
	//err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	//if err != nil {
	//	panic(err)
	//}
	//
	//fmt.Println(buf.Len())
	//
	//fmt.Println(string(buf.Bytes()))
	//
}

func NewKeyHandle(seed []byte) ([]byte, error) {
	private, err := newKey(seed)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(private.(proto.Message))
	if err != nil {
		return nil, err
	}

	s := base64.StdEncoding.EncodeToString(serializedKey)
	return []byte(s), nil
}

func newKey(seed []byte) (proto.Message, error) {
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public()

	publicProto := &ed25519pb.Ed25519PublicKey{
		Version:  0,
		KeyValue: public.(ed25519.PublicKey),
	}
	privateProto := &ed25519pb.Ed25519PrivateKey{
		Version:   0,
		PublicKey: publicProto,
		KeyValue:  private.Seed(),
	}

	return privateProto, nil
}
