// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

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

	// BlockSize must be a factor of aes.BlockSize
	BlockSize int
}

// DefaultOptions is the default options to use when creating the writer, changing might decrease
// the efficacity of the encryption.
var DefaultOptions = &Option{
	IterationsCount: 10000,
	KeyLength:       32,
	SaltLength:      64,
	Generator:       randomBytes,
	BlockSize:       bytes.MinRead,
}

// Validate the options for encoding and decoding values.
func (o *Option) Validate() error {
	if o.SaltLength < 16 {
		return errors.New("SaltLength must be at least 128 bits (16 bytes)")
	}

	if o.IterationsCount < 1000 {
		return errors.New("IterationsCount must be at least 1000")
	}

	if o.KeyLength < 14 {
		return errors.New("KeyLength must be at least 112 bits (14 bytes)")
	}

	return nil
}

func getCipherAEAD(block cipher.Block) (cipher.AEAD, error) {
	return cipher.NewGCMWithRandomNonce(block)
}

func (w *Writer) writeBlock(b []byte) error {
	encodedBytes := w.gcm.Seal(nil, nil, b, nil)

	l := make([]byte, 4)
	binary.LittleEndian.PutUint32(l, uint32(len(encodedBytes)))
	_, err := w.writer.Write(l)
	if err != nil {
		return fmt.Errorf("fail to write len of encoded data: %w", err)
	}
	_, err = w.writer.Write(encodedBytes)
	if err != nil {
		return fmt.Errorf("fail to encode data: %w", err)
	}
	return nil
}

func (r *Reader) consumeBlock() error {
	// Retrieve block information:
	// - Length of the block
	l, err := r.readBlockInfo()
	if err != nil {
		return err
	}
	encodedBytes := make([]byte, l)
	_, err = io.ReadAtLeast(r.reader, encodedBytes, l)
	if err != nil {
		r.err = fmt.Errorf("fail read the block of %d bytes: %w", l, err)
	}
	decodedBytes, err := r.gcm.Open(nil, nil, encodedBytes, nil)
	if err != nil {
		return fmt.Errorf("fail to decode bytes: %w", err)
	}
	r.buf = append(r.buf[:], decodedBytes...)
	return nil
}

func (r *Reader) readBlockInfo() (int, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadAtLeast(r.reader, buf, len(buf)); err != nil {
		return 0, err
	}
	l := binary.LittleEndian.Uint32(buf)
	return int(l), nil
}
