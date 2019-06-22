// Package hashio provides wrappers for io.Reader and io.Writer that calculate
// cryptographic hashes of the data read or written, respectively.
package hashio

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// StdCryptoHashes returns a map intended to be passed to NewHashReader or
// NewHashWriter. It contains the following hashes, "sha256", "sha1", and
// "md5", with those literal names as keys (without the quotes). It's a
// function of pure convenience.
func StdCryptoHashes() map[string]hash.Hash {
	return map[string]hash.Hash{
		"sha256": sha256.New(),
		"sha1":   sha1.New(),
		"md5":    md5.New(),
	}
}

// HashReader implements io.Reader by wrapping a provided io.Reader. It keeps
// running cryptographic hashes of data written to that provided reader.
type HashReader struct {
	io.Reader
	hashers map[string]hash.Hash
}

// NewHashReader takes an io.Reader and returns a HashReader (which implements
// io.Reader). It also takes a map of strings (used for identification purposes only)
// to hash.Hash objects. All data read from r is provided to each of these hash.Hash
// objects. If there are any errors reading from r, apart from io.EOF, the hash values
// are going to be undefined and probably incorrect.
//
// The caller should not modify the hashers map nor any of the hash.Hash objects it contains.
func NewHashReader(r io.Reader, hashers map[string]hash.Hash) *HashReader {
	writers := make([]io.Writer, 0, len(hashers))
	for _, v := range hashers {
		writers = append(writers, v)
	}

	return &HashReader{
		io.TeeReader(r, io.MultiWriter(writers...)),
		hashers,
	}
}

// Hash appends the requested hash identified by name to buf and returns the slice.
// If name does not exist in the provided hashers map passed to NewHashReader, the
// program will panic.
//
// buf can be nil.
//
// The hash value is undefined if any call to Read returned an error
// (not including io.EOF).
func (h *HashReader) Hash(name string, buf []byte) []byte {
	return h.hashers[name].Sum(buf)
}

// HexHash returns the hash identified by name as a hex encoded ASCII string.
// If name does not exist in the provided hashers map passed to NewHashReader, the
// program will panic.
//
// The returned hash is undefined if any call to Read returned an error
// (not including io.EOF).
func (h *HashReader) HexHash(name string) string {
	return fmt.Sprintf("%x", h.Hash(name, nil))
}

// HashWriter implements io.Writer by wrapping a provided io.Writer.
// As data is written to the provided io.Writer, it is also passed
// to a set of hash.Hash objects. The hashed values are made accessible
// via methods on HashWriter.
type HashWriter struct {
	io.Writer
	hashers map[string]hash.Hash
}

// NewHashWriter takes an io.Writer and returns a HashWriter (that also implements
// io.Writer). Any data written to w will also be written to each of the hash.Hash
// objects in hashers.
//
// Data is passed to each hash.Hash as it's written to w, thus any data buffered by
// w is considered for the hash function as soon as w.Write is called. If there is
// an error writing to w, then no data will be written to the hash.Hash(ers) in hashers.
// If that occurs, then no hash data is reliable and is thus undefined.
//
// The caller should not modify the hashers map nor any of the hash.Hash objects it contains.
func NewHashWriter(w io.Writer, hashers map[string]hash.Hash) *HashWriter {
	writers := make([]io.Writer, 0, len(hashers)+1)

	// w must be the first writers in writers so that any errors block hash calculations.
	writers = append(writers, w)

	for _, v := range hashers {
		writers = append(writers, v)
	}

	return &HashWriter{
		io.MultiWriter(writers...),
		hashers,
	}
}

// Hash appends the requested hash identified by name to buf and returns the slice.
// If name does not exist in the provided hashers map passed to NewHashWriter, the
// program will panic.
//
// buf can be nil.
//
// The hash value is undefined if any call to Write returned an error.
func (h *HashWriter) Hash(name string, buf []byte) []byte {
	return h.hashers[name].Sum(buf)
}

// HexHash returns the hash identified by name as a hex encoded ASCII string.
// If name does not exist in the provided hashers map passed to NewHashWriter, the
// program will panic.
//
// The returned hash is undefined if any call to Write returned an error.
func (h *HashWriter) HexHash(name string) string {
	return fmt.Sprintf("%x", h.Hash(name, nil))
}
