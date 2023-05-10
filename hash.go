/*
MIT License

# Copyright (c) 2021 Prysmatic Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package gohashtree

import (
	"fmt"
)

func _hash(digests *byte, p *byte, count uint32)

func Hash(digests [][32]byte, chunks [][32]byte) error {
	if len(chunks) == 0 {
		return nil
	}

	if len(chunks)%2 == 1 {
		return fmt.Errorf("odd number of chunks")
	}
	if len(digests) < len(chunks)/2 {
		return fmt.Errorf("not enough digest length, need at least %v, got %v", len(chunks)/2, len(digests))
	}
	if supportedCPU {
		_hash(&digests[0][0], &chunks[0][0], uint32(len(chunks)/2))
	} else {
		sha256_1_generic(digests, chunks)
	}
	return nil
}

func HashChunks(digests [][32]byte, chunks [][32]byte) {
	_hash(&digests[0][0], &chunks[0][0], uint32(len(chunks)/2))
}

func HashByteSlice(digests []byte, chunks []byte) error {
	if len(chunks) == 0 {
		return nil
	}
	if len(chunks)%64 != 0 {
		return fmt.Errorf("chunks not multiple of 64 bytes")
	}
	if len(digests)%32 != 0 {
		return fmt.Errorf("digests not multiple of 32 bytes")
	}
	if len(digests) < len(chunks)/2 {
		return fmt.Errorf("not enough digest length, need at least %d, got %d", len(chunks)/2, len(digests))
	}
	// We use an unsafe pointer to cast []byte to [][32]byte. The length and
	// capacity of the slice need to be divided accordingly by 32.
	if supportedCPU {
		_hash(&digests[0], &chunks[0], uint32(len(chunks)/64))
	} else {
		chunkedChunks := make([][32]byte, len(chunks)/32)
		for i := range chunkedChunks {
			copy(chunkedChunks[i][:], chunks[32*i:32*i+32])
		}
		chunkedDigest := make([][32]byte, len(digests)/32)
		for i := range chunkedDigest {
			copy(chunkedDigest[i][:], digests[32*i:32*i+32])
		}
		sha256_1_generic(chunkedDigest, chunkedChunks)
	}
	return nil
}
