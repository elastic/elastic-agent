// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Option is the default options used to generate the encrypt and decrypt writer.
// NOTE: the defined options need to be same for both the Reader and the writer.
type Option struct {
	Generator       bytesGen
	IterationsCount int
	KeyLength       int
	SaltLength      int
	IVLength        int

	// BlockSize must be a factor of aes.BlockSize
	BlockSize int
}

// DefaultOptions is the default options to use when creating the writer, changing might decrease
// the efficacity of the encryption.
var DefaultOptions = &Option{
	IterationsCount: 10000,
	KeyLength:       32,
	SaltLength:      64,
	IVLength:        12,
	Generator:       randomBytes,
	BlockSize:       bytes.MinRead,
}

// Validate the options for encoding and decoding values.
func (o *Option) Validate() error {
	if o.IVLength == 0 {
		return errors.New("IVLength must be superior to 0")
	}

	if o.SaltLength == 0 {
		return errors.New("SaltLength must be superior to 0")
	}

	if o.IterationsCount == 0 {
		return errors.New("IterationsCount must be superior to 0")
	}

	if o.KeyLength == 0 {
		return errors.New("KeyLength must be superior to 0")
	}

	return nil
}

func getCipherAEAD(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCM(block)
}

func (w *Writer) writeBlock(b []byte) error {
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

func (r *Reader) consumeBlock() error {
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

func (r *Reader) readBlockInfo() ([]byte, int, error) {
	buf := make([]byte, r.option.IVLength+4)
	_, err := io.ReadAtLeast(r.reader, buf, len(buf))
	if err != nil {
		return nil, 0, err
	}

	iv := buf[0:r.option.IVLength]
	l := binary.LittleEndian.Uint32(buf[r.option.IVLength:])

	return iv, int(l), nil
}
