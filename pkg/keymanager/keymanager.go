package keymanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/tink"
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/db"
	"github.com/decentralized-identity/kerigo/pkg/derivation"
)

type key struct {
	Pub     ed25519.PublicKey `json:"pub"`
	Priv    ed25519.PrivateKey
	PrivDer *derivation.Derivation
	signer  *subtle.ED25519Signer
}

type KeyManager struct {
	secrets   []string
	current   *key
	next      *key
	enveloper *aead.KMSEnvelopeAEAD
	store     db.DB
}

type Option func(*KeyManager) error

func NewKeyManager(kw tink.AEAD, store db.DB, opts ...Option) (*KeyManager, error) {

	km := &KeyManager{
		secrets: []string{},
		store:   store,
	}

	for _, o := range opts {
		err := o(km)
		if err != nil {
			return nil, err
		}
	}

	km.enveloper = aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	err := km.loadKeys()
	if err != nil {
		km.current, err = km.nextKeys()
		if err != nil {
			return nil, err
		}

		km.next, err = km.nextKeys()
		if err != nil {
			return nil, err
		}

		err := km.saveKeys()
		if err != nil {
			return nil, err
		}
	}

	return km, nil
}

func (r *KeyManager) nextKeys() (*key, error) {

	var privkey ed25519.PrivateKey
	if len(r.secrets) > 0 {
		var cur string
		cur, r.secrets = r.secrets[0], r.secrets[1:]

		der, err := derivation.FromPrefix(cur)
		if err != nil {
			return nil, err
		}
		privkey = ed25519.NewKeyFromSeed(der.Raw)

	} else {
		var err error
		_, privkey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	pubkey := privkey.Public()

	signer, err := subtle.NewED25519SignerFromPrivateKey(&privkey)
	if err != nil {
		return nil, err
	}

	nextDer, err := derivation.New(derivation.WithCode(derivation.Ed25519), derivation.WithRaw(pubkey.(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}

	return &key{
		Pub:     pubkey.(ed25519.PublicKey),
		Priv:    privkey,
		PrivDer: nextDer,
		signer:  signer,
	}, nil

}

func (r *KeyManager) Signer() derivation.Signer {
	return r.current.signer.Sign
}

func (r *KeyManager) PublicKey() ed25519.PublicKey {
	return r.current.Pub
}

func (r *KeyManager) Next() *derivation.Derivation {
	return r.next.PrivDer
}

func (r *KeyManager) Rotate() error {
	next, err := r.nextKeys()
	if err != nil {
		return err
	}

	r.current = r.next
	r.next = next
	return r.saveKeys()
}

func (r *KeyManager) saveKeys() error {
	err := r.saveKey("current", r.current)
	if err != nil {
		return err
	}

	err = r.saveKey("next", r.next)
	if err != nil {
		return err
	}

	return nil
}

func (r *KeyManager) saveKey(name string, k *key) error {
	ser, err := json.Marshal(k)
	if err != nil {
		return errors.Wrap(err, "unexpected error marshalling next key")
	}

	enc, err := r.enveloper.Encrypt(ser, []byte{})
	if err != nil {
		return errors.Wrap(err, "unexpect error trying to encrypt current key")
	}

	err = r.store.Put(name, enc)
	if err != nil {
		return errors.Wrapf(err, "unable to save key %s", name)
	}

	return nil
}

func (r *KeyManager) loadKeys() error {
	var err error
	r.current, err = r.loadKey("current")
	if err != nil {
		return err
	}

	r.next, err = r.loadKey("next")
	if err != nil {
		return err
	}

	return nil
}

func (r *KeyManager) loadKey(name string) (*key, error) {
	enc, err := r.store.Get(name)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to load key %s", name)
	}

	ser, err := r.enveloper.Decrypt(enc, []byte{})
	if err != nil {
		return nil, errors.Wrapf(err, "unable to load key %s", name)
	}

	k := &key{}
	err = json.Unmarshal(ser, k)
	if err != nil {
		return nil, errors.Wrapf(err, "unexpected error unmarshalling key %s", name)
	}

	k.signer, err = subtle.NewED25519SignerFromPrivateKey(&k.Priv)
	if err != nil {
		return nil, errors.Wrapf(err, "unexpected error creating signer for key %s", name)
	}

	return k, nil
}

func WithSecrets(s []string) Option {
	return func(km *KeyManager) error {
		km.secrets = s
		return nil
	}
}
