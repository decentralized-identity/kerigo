package main

import (
	"fmt"
	"io/ioutil"
	"time"

	bdgr "github.com/dgraph-io/badger"

	"github.com/decentralized-identity/kerigo/pkg/db/badger"
)

func main() {
	td, err := ioutil.TempDir("", "keri-*")
	if err != nil {
		panic(err)
	}

	opts := bdgr.DefaultOptions(td)
	db, err := bdgr.Open(opts)
	if err != nil {
		panic(err)
	}

	txn := db.NewTransaction(true)

	kels := badger.NewOrderedSet("kels", "/%s/%032d")

	vals := [][]byte{
		[]byte(`a`),
		[]byte(`b`),
		[]byte(`c`),
		[]byte(`z`),
		[]byte(`y`),
		[]byte(`x`),
	}

	err = kels.Put(txn, vals, "xyz", 23)
	if err != nil {
		panic(err)
	}

	fvals := [][]byte{
		[]byte(`g`),
		[]byte(`h`),
		[]byte(`i`),
		[]byte(`s`),
		[]byte(`r`),
		[]byte(`q`),
	}

	err = kels.Put(txn, fvals, "xyz", 24)
	if err != nil {
		panic(err)
	}

	sit := kels.Iterator(txn, "xyz")

	for sit.Next() {
		v := sit.Value()
		fmt.Println(string(sit.Key()), v)
	}
	sit.Close()

	fmt.Println("\nValue Iterator")
	evts := badger.NewValue("evts", "/%s/%s")

	_ = evts.Set(txn, []byte("l"), "abc", "zzz")
	_ = evts.Set(txn, []byte("m"), "abc", "ttt")
	_ = evts.Set(txn, []byte("n"), "abc", "xxx")
	_ = evts.Set(txn, []byte("o"), "abc", "jjj")
	_ = evts.Set(txn, []byte("p"), "abc", "ppp")

	eit := evts.Iterator(txn, "abc")

	for eit.Next() {
		fmt.Println(string(eit.Key()), string(eit.Value()))
	}
	eit.Close()

	fmt.Println("\nTime Iterator")
	fses := badger.NewValue("fses", "/%s/%s.%08d")

	t := time.Now()
	_ = fses.Set(txn, []byte("l"), "abc", t.Format(time.RFC3339), t.Nanosecond())
	t = time.Now()
	_ = fses.Set(txn, []byte("m"), "abc", t.Format(time.RFC3339), t.Nanosecond())
	t = time.Now()
	_ = fses.Set(txn, []byte("n"), "abc", t.Format(time.RFC3339), t.Nanosecond())
	t = time.Now()
	_ = fses.Set(txn, []byte("o"), "abc", t.Format(time.RFC3339), t.Nanosecond())
	t = time.Now()
	_ = fses.Set(txn, []byte("p"), "abc", t.Format(time.RFC3339), t.Nanosecond())

	val, _ := fses.First(txn, "abc")
	fmt.Println("First", string(val))

	val, _ = fses.Last(txn, "abc")
	fmt.Println("Last", string(val))

	fit := fses.Iterator(txn, "abc")

	for fit.Next() {
		fmt.Println(string(fit.Key()), string(fit.Value()))
	}

}

func vals() {
	td, err := ioutil.TempDir("", "keri-*")
	if err != nil {
		panic(err)
	}

	opts := bdgr.DefaultOptions(td)
	db, err := bdgr.Open(opts)
	if err != nil {
		panic(err)
	}

	txn := db.NewTransaction(true)
	kels := badger.NewOrderedSet("kels", "/%s/%032d")

	vals := [][]byte{
		[]byte(`a`),
		[]byte(`b`),
		[]byte(`c`),
		[]byte(`z`),
		[]byte(`y`),
		[]byte(`x`),
	}

	err = kels.Put(txn, vals, "xyz", 23)
	if err != nil {
		panic(err)
	}

	newvals := [][]byte{
		[]byte(`3`),
		[]byte(`2`),
		[]byte(`1`),
	}

	err = kels.Put(txn, newvals, "xyz", 23)
	if err != nil {
		panic(err)
	}

	fvals := [][]byte{
		[]byte(`123`),
		[]byte(`789`),
		[]byte(`456`),
	}

	err = kels.Put(txn, fvals, "xyz", 24)
	if err != nil {
		panic(err)
	}

	result, err := kels.Get(txn, "xyz", 23)
	if err != nil {
		panic(err)
	}

	for i, b := range result {
		fmt.Println(i, string(b))
	}

	result, err = kels.Get(txn, "xyz", 24)
	if err != nil {
		panic(err)
	}

	for i, b := range result {
		fmt.Println(i, string(b))
	}

}
