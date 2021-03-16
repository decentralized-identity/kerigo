package badger

import (
	"bytes"
	"strconv"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"

	"github.com/decentralized-identity/kerigo/pkg/derivation"
	"github.com/decentralized-identity/kerigo/pkg/event"
)

const (
	dts = "2006-01-02T15:04:05"
)

type DB struct {
	db   *badger.DB
	evts *Value      // prefix/digest = raw serialized event
	fses *Value      // prefix:datetime,monotonically incremented = event digest
	dtss *Value      // prefix:digest = ISO 8601 date time of event
	sigs *Set        // prefix:digest = multiple fully qualified event sigs
	rcts *Set        // prefix:digest = multiple non-transferable receipt couplets
	vrcs *Set        // prefix:digest = multiple transferable receipt quadlet
	kels *OrderedSet // prefix:seq no. = multiple ordered event digests as event log
	estb *OrderedSet // prefix:seq no. = multiple ordered event digests as establishment event log
	pses *OrderedSet // prefix:seq no. = multiple ordered event digests of partially signed events
	ooes *Set        // prefix:seq no. = multiple event digests as out of order escrow
	dels *Set        // prefix:seq no. = multiple event digests as duplicitous log
	ldes *Set        // prefix:seq no. = multiple event digests as likely duplicitous events
}

func New(dir string) (*DB, error) {
	opts := badger.DefaultOptions(dir)
	opts.Logger = &NoOpLogger{}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to open database at %s", dir)
	}

	out := &DB{
		db: db,
	}

	out.evts = NewValue("evts", "/%s/%s")         // prefix/digest = raw serialized event
	out.fses = NewValue("fses", "/%s/%s.%012d")   // prefix:datetime,monotonically incremented = event digest
	out.dtss = NewValue("dtss", "/%s/%s")         // prefix:digest = ISO 8601 date time of event
	out.sigs = NewSet("sigs", "/%s/%s")           // prefix:digest = multiple fully qualified event sigs
	out.rcts = NewSet("rcts", "/%s/%s")           // prefix:digest = multiple non-transferable receipt couplets
	out.vrcs = NewSet("vrcs", "/%s/%s")           // prefix:digest = multiple transferable receipt quadlet
	out.kels = NewOrderedSet("kels", "/%s/%032d") // prefix:seq no. = multiple ordered event digests as event log
	out.estb = NewOrderedSet("estb", "/%s/%032d") // prefix:seq no. = multiple ordered event digests as establishment event log
	out.pses = NewOrderedSet("pses", "/%s/%032d") // prefix:seq no. = multiple ordered event digests of partially signed events
	out.ooes = NewSet("ooes", "/%s/%032d")        // prefix:seq no. = multiple event digests as out of order escrow
	out.dels = NewSet("dels", "/%s/%032d")        // prefix:seq no. = multiple event digests as duplicitous log
	out.ldes = NewSet("ldes", "/%s/%032d")        // prefix:seq no. = multiple event digests as likely duplicitous events

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
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	vals, err := r.kels.Get(txn, pre, 0)
	return vals != nil && err == nil
}

func (r *DB) LogEvent(e *event.Message, first bool) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	sn := e.Event.SequenceInt()

	dig, err := e.Event.GetDigest()
	if err != nil {
		return err
	}

	now := time.Now()
	dts := now.Format(dts)

	if first {
		err = r.dtss.Set(txn, []byte(dts), pre, dig)
		if err != nil {
			return err
		}
	} else {
		err = r.dtss.Put(txn, []byte(dts), pre, dig)
		if err != nil {
			return err
		}
	}

	for _, sig := range e.Signatures {
		sigp := sig.AsPrefix()
		err = r.sigs.Add(txn, []byte(sigp), pre, dig)
		if err != nil {
			return err
		}
	}

	ser, err := e.Event.Serialize()
	if err != nil {
		return err
	}

	err = r.evts.Set(txn, ser, pre, dig)
	if err != nil {
		return err
	}

	err = r.kels.Add(txn, []byte(dig), pre, sn)
	if err != nil {
		return err
	}

	if e.Event.IsEstablishment() {
		err = r.estb.Add(txn, []byte(dig), pre, sn)
		if err != nil {
			return err
		}
	}

	err = r.fses.Set(txn, []byte(dig), pre, dts, now.Nanosecond())
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) LogSize(pre string) int {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	return r.kels.Count(txn, pre)
}

func (r *DB) StreamAsFirstSeen(pre string, handler func(*event.Message) error) error {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	it := r.fses.Iterator(txn, pre)
	defer it.Close()

	for it.Next() {
		dig := it.Value()
		msg, err := r.message(txn, pre, string(dig))
		if err != nil {
			return errors.Wrap(err, "")
		}
		err = handler(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *DB) StreamBySequenceNo(pre string, handler func(*event.Message) error) error {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	it := r.kels.Iterator(txn, pre)
	defer it.Close()

	fork := []byte{}
	for it.Next() {
		digs := it.Value()

		dig := digs[len(digs)-1]
		msg, err := r.message(txn, pre, string(dig))
		if err != nil {
			return errors.Wrap(err, "")
		}

		if len(fork) != 0 {
			if bytes.Compare([]byte(msg.Event.PriorEventDigest), fork) != 0 {
				break
			}
		}

		if len(digs) > 1 {
			fork = dig
		} else {
			fork = []byte{}
		}

		err = handler(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *DB) StreamPending(pre string, handler func(*event.Message) error) error {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	it := r.pses.Iterator(txn, pre)
	defer it.Close()

	for it.Next() {
		digs := it.Value()
		for _, dig := range digs {
			msg, err := r.message(txn, pre, string(dig))
			if err != nil {
				return errors.Wrap(err, "")
			}
			err = handler(msg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *DB) StreamEstablisment(pre string, handler func(*event.Message) error) error {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	it := r.estb.Iterator(txn, pre)
	defer it.Close()

	for it.Next() {
		digs := it.Value()
		msg, err := r.message(txn, pre, string(digs[0]))
		if err != nil {
			return errors.Wrap(err, "")
		}
		err = handler(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *DB) CurrentEvent(pre string) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	dig, err := r.fses.Last(txn, pre)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last event digest")
	}
	return r.message(txn, pre, string(dig))
}

func (r *DB) CurrentEstablishmentEvent(pre string) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	digs, err := r.estb.Last(txn, pre)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last event digest")
	}

	return r.message(txn, pre, string(digs[len(digs)-1]))
}

func (r *DB) Inception(pre string) (*event.Message, error) {
	return r.EventAt(pre, 0)
}

func (r *DB) Signatures(pre, dig string) ([]derivation.Derivation, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()
	return r.signatures(txn, pre, dig)
}

func (r *DB) signatures(txn *badger.Txn, pre, dig string) ([]derivation.Derivation, error) {
	s, err := r.sigs.Get(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get signatures")
	}

	out := make([]derivation.Derivation, len(s))
	for i, b := range s {
		der, err := derivation.FromAttachedSignature(string(b))
		if err != nil {
			return nil, errors.Wrap(err, "invalid derivation")
		}
		out[i] = *der
	}

	return out, nil
}

func (r *DB) transferableRcpts(txn *badger.Txn, pre, dig string) ([][]byte, error) {
	s, err := r.vrcs.Get(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get signatures")
	}

	return s, nil
}

func (r *DB) nonTransferableRcpts(txn *badger.Txn, pre, dig string) ([][]byte, error) {
	s, err := r.rcts.Get(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get signatures")
	}

	return s, nil
}

func (r *DB) Event(pre, dig string) (*event.Event, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()
	return r.event(txn, pre, dig)
}

func (r *DB) event(txn *badger.Txn, pre, dig string) (*event.Event, error) {
	d, err := r.evts.Get(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "raw event not found")
	}

	evt, err := event.Deserialize(d, event.JSON)
	if err != nil {
		return nil, errors.Wrap(err, "invalid data stored at raw event")
	}

	return evt, nil
}

func (r *DB) Message(pre, dig string) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()
	return r.message(txn, pre, dig)
}

func (r *DB) message(txn *badger.Txn, pre, dig string) (*event.Message, error) {
	evt, err := r.event(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to load raw event")
	}

	sigs, err := r.signatures(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to load signatures")
	}

	bvrcs, err := r.transferableRcpts(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to load receipts")
	}

	brcts, err := r.nonTransferableRcpts(txn, pre, dig)
	if err != nil {
		return nil, errors.Wrap(err, "unable to load receipts")
	}

	vrcs := make([]*event.Receipt, len(bvrcs))
	for i, bvrc := range bvrcs {
		quad, err := event.ParseAttachedQuadlet(bytes.NewReader(bvrc))
		if err != nil {
			return nil, errors.Wrap(err, "unable to parse quadlet")
		}

		rcpt, err := event.NewReceipt(evt,
			event.WithQB64(bvrc),
			event.WithSignature(quad.Signature),
			event.WithEstablishmentSeal(&event.Seal{
				Prefix:   quad.Prefix.AsPrefix(),
				Sequence: strconv.Itoa(quad.Sequence),
				Digest:   quad.Digest.AsPrefix(),
			}),
		)

		vrcs[i] = rcpt
	}

	rcts := make([]*event.Receipt, len(brcts))
	for i, brct := range brcts {
		couple, err := event.ParseAttachedCouplet(bytes.NewReader(brct))
		if err != nil {
			return nil, errors.Wrap(err, "unable to hydrate new receipt")
		}

		rcpt, err := event.NewReceipt(evt,
			event.WithQB64(brct),
			event.WithSignerPrefix(couple.Prefix.AsPrefix()),
			event.WithSignature(couple.Signature))
		if err != nil {
			return nil, err
		}

		rcts[i] = rcpt
	}

	return &event.Message{
		Event:                   evt,
		Signatures:              sigs,
		TransferableReceipts:    vrcs,
		NonTransferableReceipts: rcts,
	}, nil
}

func (r *DB) EventAt(pre string, sn int) (*event.Message, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	d, err := r.kels.Get(txn, pre, sn)
	if err != nil || len(d) != 1 {
		return nil, errors.New("multiple inception events for log")
	}

	dig := string(d[0])
	return r.message(txn, pre, dig)
}

func (r *DB) EscrowPendingEvent(e *event.Message) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	dig, err := e.Event.GetDigest()
	if err != nil {
		return err
	}

	dts := time.Now().Format(time.RFC3339)

	err = r.dtss.Put(txn, []byte(dts), pre, dig)
	if err != nil {
		return err
	}

	for _, sig := range e.Signatures {
		sigp := sig.AsPrefix()
		err = r.sigs.Add(txn, []byte(sigp), pre, dig)
		if err != nil {
			return err
		}
	}

	ser, err := e.Event.Serialize()
	if err != nil {
		return err
	}

	err = r.evts.Set(txn, ser, pre, dig)
	if err != nil {
		return err
	}

	err = r.pses.Add(txn, []byte(dig), pre, e.Event.SequenceInt())
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) RemovePendingEscrow(prefix string, sn int, dig string) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	err := r.pses.RemoveFromSet(txn, []byte(dig), prefix, sn)
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) EscrowOutOfOrderEvent(e *event.Message) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	dig, err := e.Event.GetDigest()
	if err != nil {
		return err
	}

	dts := time.Now().Format(time.RFC3339)

	err = r.dtss.Put(txn, []byte(dts), pre, dig)
	if err != nil {
		return err
	}

	for _, sig := range e.Signatures {
		sigp := sig.AsPrefix()
		err = r.sigs.Add(txn, []byte(sigp), pre, dig)
		if err != nil {
			return err
		}
	}

	ser, err := e.Event.Serialize()
	if err != nil {
		return err
	}

	err = r.evts.Set(txn, ser, pre, dig)
	if err != nil {
		return err
	}

	err = r.ooes.Add(txn, []byte(dig), pre, e.Event.SequenceInt())
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) EscrowLikelyDuplicitiousEvent(e *event.Message) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := e.Event.Prefix
	dig, err := e.Event.GetDigest()
	if err != nil {
		return err
	}

	dts := time.Now().Format(time.RFC3339)

	err = r.dtss.Put(txn, []byte(dts), pre, dig)
	if err != nil {
		return err
	}

	for _, sig := range e.Signatures {
		sigp := sig.AsPrefix()
		err = r.sigs.Add(txn, []byte(sigp), pre, dig)
		if err != nil {
			return err
		}
	}

	ser, err := e.Event.Serialize()
	if err != nil {
		return err
	}

	err = r.evts.Set(txn, ser, pre, dig)
	if err != nil {
		return err
	}

	err = r.ldes.Add(txn, []byte(dig), pre, e.Event.SequenceInt())
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) LastAcceptedDigest(pre string, seq int) ([]byte, error) {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	vals, err := r.kels.Last(txn, pre, seq)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last event")
	}

	if len(vals) == 0 {
		return nil, errors.New("not found")
	}

	return vals[len(vals)-1], nil
}

func (r *DB) LogTransferableReceipt(vrc *event.Receipt) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := vrc.Prefix
	dig := vrc.Digest

	quadlet := vrc.Text()

	err := r.vrcs.Add(txn, quadlet, pre, dig)
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) LogNonTransferableReceipt(rct *event.Receipt) error {
	txn := r.db.NewTransaction(true)
	defer txn.Discard()

	pre := rct.Prefix
	dig := rct.Digest
	couplet := rct.Text()

	err := r.rcts.Add(txn, couplet, pre, dig)
	if err != nil {
		return err
	}

	return txn.Commit()
}

func (r *DB) StreamTransferableReceipts(pre string, sn int, handler func(quadlet []byte) error) error {
	txn := r.db.NewTransaction(false)
	defer txn.Discard()

	vals, err := r.vrcs.Get(txn, pre, sn)
	if err != nil {
		return errors.New("not found")
	}

	for _, val := range vals {
		err = handler(val)
		if err != nil {
			return err
		}
	}

	return nil
}
