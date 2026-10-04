package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

const magic = "WHOME1\x00" // legacy reader compatibility
const magicV2 = "WHOME2\x00"
const chunkSize = 4 * 1024 * 1024

func encryptStream(dst io.Writer, src io.Reader) (int64, error) {
	return encryptStreamForPath(dst, src, "")
}

func streamAAD(rel string, fileID []byte, index, total uint64, manifest bool) []byte {
	kind := "chunk"
	if manifest {
		kind = "manifest"
	}
	return []byte(fmt.Sprintf("warden-home:v2:%s:%x:%s:%d:%d", rel, fileID, kind, index, total))
}

func encryptStreamForPath(dst io.Writer, src io.Reader, rel string) (int64, error) {
	if _, err := dst.Write([]byte(magicV2)); err != nil {
		return 0, err
	}
	fileID := make([]byte, 16)
	if _, err := rand.Read(fileID); err != nil {
		return 0, err
	}
	if _, err := dst.Write(fileID); err != nil {
		return 0, err
	}
	buf := make([]byte, chunkSize)
	var total int64
	var index uint64
	for {
		n, readErr := io.ReadFull(src, buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return total, readErr
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return total, err
		}
		sealed := aead.Seal(nil, nonce, buf[:n], streamAAD(rel, fileID, index, 0, false))
		if err := binary.Write(dst, binary.BigEndian, uint32(len(sealed))); err != nil {
			return total, err
		}
		if _, err := dst.Write(nonce); err != nil {
			return total, err
		}
		if _, err := dst.Write(sealed); err != nil {
			return total, err
		}
		total += int64(n)
		index++
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	// An authenticated terminal record makes truncation detectable and binds
	// the exact number and total plaintext length of all preceding chunks.
	if err := binary.Write(dst, binary.BigEndian, uint32(0)); err != nil {
		return total, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return total, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return total, err
	}
	if err := binary.Write(dst, binary.BigEndian, uint64(total)); err != nil {
		return total, err
	}
	if err := binary.Write(dst, binary.BigEndian, index); err != nil {
		return total, err
	}
	tag := aead.Seal(nil, nonce, nil, streamAAD(rel, fileID, index, uint64(total), true))
	if _, err := dst.Write(tag); err != nil {
		return total, err
	}
	return total, nil
}

func decryptStream(dst io.Writer, src io.Reader) error {
	return decryptStreamForPath(dst, src, "")
}

func decryptStreamForPath(dst io.Writer, src io.Reader, rel string) error {
	header := make([]byte, len(magic))
	if _, err := io.ReadFull(src, header); err != nil {
		return errors.New("invalid encrypted file")
	}
	if string(header) == magic {
		return decryptLegacyStream(dst, src)
	}
	if string(header) != magicV2 {
		return errors.New("invalid encrypted file")
	}
	fileID := make([]byte, 16)
	if _, err := io.ReadFull(src, fileID); err != nil {
		return errors.New("invalid encrypted file identity")
	}
	var index, total uint64
	for {
		var size uint32
		if err := binary.Read(src, binary.BigEndian, &size); err != nil {
			return err
		}
		if size == 0 {
			nonce := make([]byte, aead.NonceSize())
			if _, err := io.ReadFull(src, nonce); err != nil {
				return err
			}
			var expectedTotal, expectedChunks uint64
			if err := binary.Read(src, binary.BigEndian, &expectedTotal); err != nil {
				return err
			}
			if err := binary.Read(src, binary.BigEndian, &expectedChunks); err != nil {
				return err
			}
			tag := make([]byte, aead.Overhead())
			if _, err := io.ReadFull(src, tag); err != nil {
				return err
			}
			if expectedTotal != total || expectedChunks != index {
				return errors.New("encrypted file manifest mismatch")
			}
			if _, err := aead.Open(nil, nonce, tag, streamAAD(rel, fileID, index, total, true)); err != nil {
				return errors.New("encrypted file manifest authentication failed")
			}
			var trailing [1]byte
			if n, _ := src.Read(trailing[:]); n != 0 {
				return errors.New("unexpected encrypted file trailer")
			}
			return nil
		}
		if size > chunkSize+uint32(aead.Overhead()) {
			return errors.New("invalid chunk")
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(src, sealed); err != nil {
			return err
		}
		plain, err := aead.Open(nil, nonce, sealed, streamAAD(rel, fileID, index, 0, false))
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
		total += uint64(len(plain))
		index++
	}
}

func decryptLegacyStream(dst io.Writer, src io.Reader) error {
	for {
		var size uint32
		if err := binary.Read(src, binary.BigEndian, &size); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if size > chunkSize+uint32(aead.Overhead()) {
			return errors.New("invalid chunk")
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(src, nonce); err != nil {
			return err
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(src, sealed); err != nil {
			return err
		}
		plain, err := aead.Open(nil, nonce, sealed, nil)
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
	}
}

func metadataAAD(rel string, size, mtime int64) []byte {
	return []byte(fmt.Sprintf("warden-home:metadata:v2:%s:%d:%d", filepath.ToSlash(rel), size, mtime))
}

// Bind the plaintext digest into authenticated metadata. Old v2 files remain
// readable; their digest is calculated from authenticated plaintext on listing.
func metadataHashAAD(rel string, m metadata) []byte {
	if m.SHA256 == "" {
		return metadataAAD(rel, m.Size, m.ModTime)
	}
	return []byte(fmt.Sprintf("warden-home:metadata:v3:%s:%d:%d:%s", filepath.ToSlash(rel), m.Size, m.ModTime, m.SHA256))
}
