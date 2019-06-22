package hashio

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var (
	dataFile       = "testdata/input_file"
	dataFileMD5    = "31ee0d920506236319ae5e1005f48e45"
	dataFileSHA1   = "c447a7b45cc543e1fb2759d57255c4b300c6bf1e"
	dataFileSHA256 = "535a643ba2af1f027e370b9e74eb0823ea886322ef0c96733e374d7ee334a258"
)

func ExampleHashReader() {
	reader := NewHashReader(strings.NewReader("hello I am happy"), map[string]hash.Hash{"sha256": sha256.New()})
	if _, err := ioutil.ReadAll(reader); err != nil {
		// handle error
	}

	fmt.Println(reader.HexHash("sha256"))

	// Output: 1963f25b4f1f410e5702a9bcb2d44a44a43aaea0ef4f946ddb24c1472155a13a
}

func TestHashReader(t *testing.T) {
	f, err := os.Open(dataFile)
	if err != nil {
		t.Fatalf("Unable to open %q: %v", dataFile, err)
	}
	defer f.Close()

	hashers := make(map[string]hash.Hash)
	hashers["sha256"] = sha256.New()
	hashers["md5"] = md5.New()
	hashers["sha1"] = sha1.New()

	hr := NewHashReader(f, hashers)
	if _, err := ioutil.ReadAll(hr); err != nil {
		t.Fatalf("ioutil.ReadAll([from: %q]): %v", dataFile, err)
	}

	if hash := hr.HexHash("sha256"); hash != dataFileSHA256 {
		t.Errorf("HashReader.HexHash(sha256) got: %q, wanted %q", hash, dataFileSHA256)
	}

	if hash := hr.HexHash("sha1"); hash != dataFileSHA1 {
		t.Errorf("HashReader.HexHash(sha1) got: %q, wanted %q", hash, dataFileSHA1)
	}

	if hash := hr.HexHash("md5"); hash != dataFileMD5 {
		t.Errorf("HashReader.HexHash(md5) got: %q, wanted %q", hash, dataFileMD5)
	}
}

func ExampleHashWriter() {
	sb := &strings.Builder{}
	writer := NewHashWriter(sb, map[string]hash.Hash{"sha256": sha256.New()})
	_, _ = writer.Write([]byte("hello I am happy")) // error checking elided for example

	fmt.Println(writer.HexHash("sha256"))

	// Output: 1963f25b4f1f410e5702a9bcb2d44a44a43aaea0ef4f946ddb24c1472155a13a
}

func TestHashReaderAndWriter(t *testing.T) {
	f, err := os.Open(dataFile)
	if err != nil {
		t.Fatalf("Unable to open %q: %v", dataFile, err)
	}
	defer f.Close()

	hashers := make(map[string]hash.Hash)
	hashers["sha256"] = sha256.New()
	hashers["md5"] = md5.New()
	hashers["sha1"] = sha1.New()

	hr := NewHashReader(f, hashers)
	contents, err := ioutil.ReadAll(hr)
	if err != nil {
		t.Fatalf("ioutil.ReadAll([from: %q]): %v", dataFile, err)
	}

	if hash := hr.HexHash("sha256"); hash != dataFileSHA256 {
		t.Errorf("HashReader.HexHash(sha256) got: %q, wanted %q", hash, dataFileSHA256)
	}

	if hash := hr.HexHash("sha1"); hash != dataFileSHA1 {
		t.Errorf("HashReader.HexHash(sha1) got: %q, wanted %q", hash, dataFileSHA1)
	}

	if hash := hr.HexHash("md5"); hash != dataFileMD5 {
		t.Errorf("HashReader.HexHash(md5) got: %q, wanted %q", hash, dataFileMD5)
	}

	hashers = make(map[string]hash.Hash)
	hashers["sha256"] = sha256.New()
	hashers["md5"] = md5.New()
	hashers["sha1"] = sha1.New()

	buf := bytes.NewBuffer(nil)
	hw := NewHashWriter(buf, hashers)
	n, err := hw.Write(contents)
	if err != nil {
		t.Errorf("HashWriter.Write: %v", err)
	}
	if n != len(contents) {
		t.Errorf("HashWriter.Write wrote: %d bytes, wanted %d bytes", n, len(contents))
	}

	if hash := hw.HexHash("sha256"); hash != dataFileSHA256 {
		t.Errorf("HashWriter.HexHash(sha256) got: %q, wanted %q", hash, dataFileSHA256)
	}

	if hash := hw.HexHash("sha1"); hash != dataFileSHA1 {
		t.Errorf("HashWriter.HexHash(sha1) got: %q, wanted %q", hash, dataFileSHA1)
	}

	if hash := hw.HexHash("md5"); hash != dataFileMD5 {
		t.Errorf("HashWriter.HexHash(md5) got: %q, wanted %q", hash, dataFileMD5)
	}

}
