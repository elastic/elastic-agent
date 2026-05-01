// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"

	"github.com/stretchr/testify/require"
)

// testWriter is a v2 writer that uses NewGCM, not NewGCMWithRandomNonce
// This was the behaviour pre 9.4
type testWriter struct {
	option    *Option
	password  []byte
	writer    io.Writer
	generator bytesGen

	// internal
	wroteHeader bool
	err         error
	gcm         cipher.AEAD
	salt        []byte
}

func NewTestWriter(writer io.Writer, password []byte) (*testWriter, error) {
	option := DefaultOptions
	if err := option.Validate(); err != nil {
		return nil, err
	}

	var g bytesGen
	if option.Generator == nil {
		g = randomBytes
	} else {
		g = option.Generator
	}

	salt, err := g(option.SaltLength)
	if err != nil {
		return nil, fmt.Errorf("fail to generate random password salt: %w", err)
	}

	return &testWriter{
		option:    option,
		password:  password,
		generator: g,
		writer:    writer,
		salt:      salt,
	}, nil
}

func (w *testWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	if !w.wroteHeader {
		w.wroteHeader = true

		// Stretch the user provided key.
		passwordBytes, err := stretchPassword(
			w.password,
			w.salt,
			w.option.IterationsCount,
			w.option.KeyLength,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to stretch password: %w", err)
		}

		// Select AES-256: because len(passwordBytes) == 32 bytes.
		block, err := aes.NewCipher(passwordBytes)
		if err != nil {
			w.err = fmt.Errorf("could not create the cipher to encrypt: %w", err)
			return 0, w.err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			w.err = fmt.Errorf("could not create the GCM to encrypt: %w", err)
			return 0, w.err
		}

		w.gcm = aesgcm

		// Write headers
		// VERSION|SALT|IV|PAYLOAD
		header := new(bytes.Buffer)
		header.Write(versionMagicHeader)
		header.Write(w.salt)

		n, err := w.writer.Write(header.Bytes())
		if err != nil {
			w.err = fmt.Errorf("fail to write encoding information header: %w", err)
			return 0, w.err
		}

		if n != len(header.Bytes()) {
			w.err = errors.New("written bytes do not match header size")
		}

		if err := w.writeBlock(b); err != nil {
			return 0, fmt.Errorf("fail to write block: %w", err)
		}

		return len(b), err
	}

	if err := w.writeBlock(b); err != nil {
		return 0, fmt.Errorf("fail to write block: %w", err)
	}

	return len(b), nil
}

func (w *testWriter) writeBlock(b []byte) error {
	// randomly generate the salt and the initialization vector, this information will be saved
	// on disk in the file as part of the header
	iv, err := w.generator(w.option.IVLength)
	if err != nil {
		w.err = fmt.Errorf("fail to generate random IV: %w", err)
		return w.err
	}

	//nolint:errcheck // Ignore the error at this point.
	w.writer.Write(iv)

	encodedBytes := w.gcm.Seal(nil, iv, b, nil)

	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, uint32(len(encodedBytes))) //nolint:gosec // ignoring unsafe type conversion
	//nolint:errcheck // Ignore the error at this point.
	w.writer.Write(l)

	_, err = w.writer.Write(encodedBytes)
	if err != nil {
		return fmt.Errorf("fail to encode data: %w", err)
	}

	return nil
}

// testReader is a v2 reader that uses NewGCM, not NewGCMWithRandomNonce
// This was the behaviour pre 9.4
type testReader struct {
	option   *Option
	password []byte
	reader   io.Reader

	// internal
	err        error
	readHeader bool
	gcm        cipher.AEAD
	buf        []byte
	eof        bool
}

func NewTestReader(reader io.Reader, password []byte) (*testReader, error) {
	option := DefaultOptions
	if reader == nil {
		return nil, errors.New("missing reader")
	}

	return &testReader{
		option:   option,
		password: password,
		reader:   reader,
	}, nil
}

func (r *testReader) Read(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	// Lets read the header.
	if !r.readHeader {
		r.readHeader = true
		vLen := len(versionMagicHeader)
		buf := make([]byte, vLen+r.option.SaltLength)
		n, err := io.ReadAtLeast(r.reader, buf, len(buf))
		if err != nil {
			r.err = fmt.Errorf("fail to read encoding header: %w", err)
			return n, err
		}

		v := buf[0:vLen]
		if !bytes.Equal(versionMagicHeader, v) {
			return 0, fmt.Errorf("unknown version %s (%+v)", string(v), v)
		}

		salt := buf[vLen : vLen+r.option.SaltLength]

		// Stretch the user provided key.
		passwordBytes, err := stretchPassword(
			r.password,
			salt,
			r.option.IterationsCount,
			r.option.KeyLength,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to stretch password: %w", err)
		}

		block, err := aes.NewCipher(passwordBytes)
		if err != nil {
			r.err = fmt.Errorf("could not create the cipher to decrypt the data: %w", err)
			return 0, r.err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			r.err = fmt.Errorf("could not create the GCM to decrypt the data: %w", err)
			return 0, r.err
		}
		r.gcm = aesgcm
	}

	return r.readTo(b)
}

func (r *testReader) readTo(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	if !r.eof {
		if err := r.consumeBlock(); err != nil {
			// We read all the blocks
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				r.eof = true
			} else {
				r.err = err
				return 0, err
			}
		}
	}

	n := copy(b, r.buf)
	r.buf = r.buf[n:]

	if r.eof && len(r.buf) == 0 {
		r.err = io.EOF
	}

	return n, r.err
}

func (r *testReader) consumeBlock() error {
	// Retrieve block information:
	// - Initialization vector
	// - Length of the block
	iv, l, err := r.readBlockInfo()
	if err != nil {
		return err
	}

	encodedBytes := make([]byte, l)
	_, err = io.ReadAtLeast(r.reader, encodedBytes, l)
	if err != nil {
		r.err = fmt.Errorf("fail read the block of %d bytes: %w", l, err)
	}

	decodedBytes, err := r.gcm.Open(nil, iv, encodedBytes, nil)
	if err != nil {
		return fmt.Errorf("fail to decode bytes: %w", err)
	}
	r.buf = append(r.buf[:], decodedBytes...)

	return nil
}

func (r *testReader) readBlockInfo() ([]byte, int, error) {
	buf := make([]byte, r.option.IVLength+4)
	_, err := io.ReadAtLeast(r.reader, buf, len(buf))
	if err != nil {
		return nil, 0, err
	}

	iv := buf[0:r.option.IVLength]
	l := binary.LittleEndian.Uint32(buf[r.option.IVLength:])

	return iv, int(l), nil
}

// TestCryptoInterop are tests ensure that our uses of NewGCMWithRandomNonce can fully replace NewGCM
// - a reader that uses NewGCMWithRandomNonce can read something encrypted with NewGCM (upgrade scenario)
// - a reader that uses NewGCM can read something encrypted with NewGCMWithRandomNonce (rollback)
func TestCryptoInterop(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "Test explicitly uses NewGCM and NewGCMWithRandomNonce in order to test compatibility.")
	// Use two messages so that the entire encrypted data has the format:
	// v2 | SALT | IV(1) | LEN(1) | ENCRYPTED-BYTES(1) | IV(2) | LEN(2) | ENCRYPTED-BYTES(2)
	msg1 := []byte(`Hello, world!`)
	msg2 := []byte(`This is a message.`)
	fullMsg := slices.Concat(msg1, msg2)
	password := []byte(`secret-password`)
	t.Run("New reader can read old writer output", func(t *testing.T) {
		var buf bytes.Buffer
		wr, err := NewTestWriter(&buf, password)
		require.NoError(t, err)

		n, err := wr.Write(msg1)
		require.NoError(t, err)
		require.Equal(t, len(msg1), n)
		n, err = wr.Write(msg2)
		require.NoError(t, err)
		require.Equal(t, len(msg2), n)

		r, err := NewReaderWithDefaults(&buf, password)
		require.NoError(t, err)
		p, err := io.ReadAll(r)
		require.NoError(t, err)
		require.EqualValues(t, fullMsg, p)
	})
	t.Run("Old reader can read new writer output", func(t *testing.T) {
		var buf bytes.Buffer
		wr, err := NewWriterWithDefaults(&buf, password)
		require.NoError(t, err)

		n, err := wr.Write(msg1)
		require.NoError(t, err)
		require.Equal(t, len(msg1), n)
		n, err = wr.Write(msg2)
		require.NoError(t, err)
		require.Equal(t, len(msg2), n)

		r, err := NewTestReader(&buf, password)
		require.NoError(t, err)
		p, err := io.ReadAll(r)
		require.NoError(t, err)
		require.EqualValues(t, fullMsg, p)
	})
}
