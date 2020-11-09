package derivation

// Basic derivations are just byte representations of data.
func basicDeriver() deriver {
	return func(data []byte) ([]byte, error) {
		return data, nil
	}
}
