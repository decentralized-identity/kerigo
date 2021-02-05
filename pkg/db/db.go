package db

type DB interface {
	Put(k string, v []byte) error
	Get(k string) ([]byte, error)
}

type Iterator interface {
}
