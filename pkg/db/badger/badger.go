package badger

import (
	"encoding/json"
	"fmt"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/event"
)

const (
	Evt  = "evt"
	Raw  = "raw"
	Fork = "frk"
	Est  = "est"

	EvtPrefix = "%s{evt}"
	EstPrefix = "%s{est}"

	EvtKey  = "%s{evt}%032d"
	RawKey  = "%s{raw}%s"
	ForkKey = "%s{frk}%032d"
	EstKey  = "%s{est}%032d"
)

type DB struct {
	db *badger.DB
}

func New(dir string) (*DB, error) {
	db, err := badger.Open(badger.DefaultOptions(dir))
	if err != nil {
		return nil, errors.Wrapf(err, "unable to open database at %s", dir)
	}

	out := &DB{
		db: db,
	}

	return out, nil
}

func (r *DB) Close() error {
	return r.db.Close()
}

func (r *DB) Put(k string, v []byte) error {
	err := r.db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(k), v)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return errors.Wrap(err, "error putting to badger")
	}

	return nil
}

func (r *DB) Get(k string) ([]byte, error) {

	var val []byte
	err := r.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(k))
		if err != nil {
			return err
		}

		err = item.Value(func(v []byte) error {
			val = append([]byte{}, v...)
			return nil
		})

		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "error getting from badger")
	}

	return val, nil
}

func (r *DB) Seen(pre string) bool {
	found := false
	_ = r.db.View(func(txn *badger.Txn) error {
		evtk := fmt.Sprintf(EvtKey, pre, 0)
		_, err := txn.Get([]byte(evtk))
		if err == nil {
			found = true
		}
		return nil
	})

	return found
}

func (r *DB) ForkEvent(e *event.Message) error {
	if e.Event.ILK() != event.IXN {
		return errors.New("only IXN events can be forked")
	}

	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	sn := e.Event.SequenceInt()
	dig, err := e.Event.GetDigest()
	if err != nil {
		return errors.Wrap(err, "store event error, unable to get event digest")
	}

	evtk := fmt.Sprintf(EvtKey, pre, sn)
	err = txn.Delete([]byte(evtk))
	if err == nil {
		return fmt.Errorf("event doesn't exist for %s at %d", pre, sn)
	}

	frk := fmt.Sprintf(ForkKey, pre, sn)
	err = txn.Set([]byte(frk), []byte(dig))
	if err != nil {
		return err
	}

	//TODO: move any trailing events off the log and into the forked branch

	return txn.Commit()
}

func (r *DB) LogEvent(e *event.Message) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	sn := e.Event.SequenceInt()
	dig, err := e.Event.GetDigest()
	if err != nil {
		return errors.Wrap(err, "store event error, unable to get event digest")
	}

	evtk := fmt.Sprintf(EvtKey, pre, sn)
	_, err = txn.Get([]byte(evtk))
	if err == nil {
		return fmt.Errorf("fork error, event already exists for %s at %d", pre, sn)
	}

	rawk := fmt.Sprintf(RawKey, pre, dig)
	v, err := json.Marshal(e)
	if err != nil {
		return errors.Wrap(err, "unable to [cbor] serialize event to store")
	}

	err = txn.Set([]byte(rawk), v)
	if err != nil {
		return err
	}

	err = txn.Set([]byte(evtk), []byte(dig))
	if err != nil {
		return err
	}

	if e.Event.IsEstablishment() {
		estk := fmt.Sprintf(EstKey, pre, sn)
		err = txn.Set([]byte(estk), []byte(dig))
		if err != nil {
			return err
		}
	}

	return txn.Commit()
}

func (r *DB) LogSize(pre string) int {
	count := 0
	err := r.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(fmt.Sprintf(EvtPrefix, pre))
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}

		return nil
	})

	if err != nil {
		return 0
	}

	return count
}

func (r *DB) StreamLog(pre string, handler func(*event.Message)) error {
	return r.streamLog(pre, Evt, handler)
}

func (r *DB) StreamForks(pre string, handler func(*event.Message)) error {
	return r.streamLog(pre, Fork, handler)
}

func (r *DB) StreamEstablisment(pre string, handler func(*event.Message)) error {
	return r.streamLog(pre, Est, handler)
}

func (r *DB) streamLog(pre, typ string, handler func(*event.Message)) error {
	err := r.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(fmt.Sprintf("%s{%s}", pre, typ))

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()

			var msg *event.Message
			err := item.Value(func(dig []byte) error {
				var err error
				msg, err = r.loadRawEvent(pre, string(dig), txn)

				return err
			})

			if err != nil {
				return errors.Wrap(err, "")
			}

			handler(msg)
		}

		return nil
	})

	if err != nil {
		return errors.Wrapf(err, "error streaming log for %s", pre)
	}

	return nil
}

func (r *DB) CurrentEvent(pre string) (*event.Message, error) {
	return r.distalEvt(pre, Evt, true)
}

func (r *DB) CurrentEstablishmentEvent(pre string) (*event.Message, error) {
	return r.distalEvt(pre, Est, true)
}

func (r *DB) Inception(pre string) (*event.Message, error) {
	evt, err := r.distalEvt(pre, Evt, false)
	if err != nil {
		return nil, err
	}

	if evt.Event.ILK() != event.ICP {
		return nil, errors.New("invalid log state, first event is not ICP")
	}

	return evt, nil
}

func (r *DB) EventAt(pre string, sn int) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	evtk := fmt.Sprintf(EvtKey, pre, sn)
	item, err := txn.Get([]byte(evtk))
	if err != nil {
		return nil, errors.Wrapf(err, "no event for %s at %d", pre, sn)
	}

	var msg *event.Message
	err = item.Value(func(dig []byte) error {
		var err error
		msg, err = r.loadRawEvent(pre, string(dig), txn)

		return err
	})

	if err != nil {
		return nil, errors.Wrap(err, "unable to load raw event")
	}

	return msg, nil

}

func (r *DB) distalEvt(pre, typ string, reverse bool) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	opts := badger.DefaultIteratorOptions
	opts.Reverse = reverse

	it := txn.NewIterator(opts)
	defer it.Close()

	seek := fmt.Sprintf("%s{%s}", pre, typ)
	if reverse {
		seek += "~"
	}

	it.Rewind()
	it.Seek([]byte(seek))
	if !it.Valid() {
		return nil, errors.New("not found")
	}

	item := it.Item()

	var msg *event.Message
	err := item.Value(func(dig []byte) error {
		var err error
		msg, err = r.loadRawEvent(pre, string(dig), txn)

		return err
	})

	if err != nil {
		return nil, errors.Wrap(err, "unable to load raw event")
	}

	return msg, err

}

func (r *DB) loadRawEvent(pre, dig string, txn *badger.Txn) (*event.Message, error) {
	rawk := fmt.Sprintf(RawKey, pre, dig)

	item, err := txn.Get([]byte(rawk))
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get raw event: %s", rawk)
	}

	msg := &event.Message{Event: &event.Event{Config: nil}}

	err = item.Value(func(val []byte) error {
		err = json.Unmarshal(val, msg)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal raw event")
	}

	return msg, nil

}
