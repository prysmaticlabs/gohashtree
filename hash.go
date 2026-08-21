/*
MIT License

# Copyright (c) 2021-2025 Prysmatic Labs

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
	"unsafe"
)

const (
	chunkSize       = 32 // bytes in one chunk
	chunksPerDigest = 2

	// widestAsmBatch is how many digests the widest dispatch path (AVX-512)
	// emits per loop iteration. AVX2 and AVX take 8 and 4, which divide it, so
	// a whole number of these iterations leaves no scalar tail on any path.
	widestAsmBatch   = 16
	chunksPerAsmIter = chunksPerDigest * widestAsmBatch

	// maxAsmBytes is how much input one _hash call may take. _hash is assembly,
	// which the runtime never treats as an asynchronous preemption point, so a
	// call covering a whole Merkle layer holds up every goroutine in the
	// process for as long as it runs whenever the collector stops the world.
	maxAsmBytes = 64 * 1024

	// maxAsmChunks is that budget in chunks, truncated to whole iterations.
	maxAsmChunks = maxAsmBytes / chunkSize / chunksPerAsmIter * chunksPerAsmIter
)

// hashChunked feeds _hash at most maxAsmChunks at a time. Between calls the
// goroutine is in Go code, where a collection can preempt it.
func hashChunked(digests [][32]byte, chunks [][32]byte) {
	for len(chunks) > maxAsmChunks {
		_hash(&digests[0][0], chunks[:maxAsmChunks], maxAsmChunks/2)
		chunks = chunks[maxAsmChunks:]
		digests = digests[maxAsmChunks/2:]
	}
	_hash(&digests[0][0], chunks, uint32(len(chunks)/2))
}

// Hash hashes the chunks two at the time and outputs the digests on the first
// argument. It does check for lengths on the inputs.
func Hash(digests [][32]byte, chunks [][32]byte) error {
	if len(chunks) == 0 {
		return nil
	}

	if len(chunks)%2 == 1 {
		return ErrOddChunks
	}
	if len(digests) < len(chunks)/2 {
		return fmt.Errorf("%w: need at least %v, got %v", ErrNotEnoughDigests, len(chunks)/2, len(digests))
	}
	if supportedCPU {
		hashChunked(digests, chunks)
	} else {
		sha256_1_generic(digests, chunks)
	}
	return nil
}

// HashChunks is the same as Hash, but does not do error checking on the lengths of the slices
func HashChunks(digests [][32]byte, chunks [][32]byte) {
	if supportedCPU {
		hashChunked(digests, chunks)
	} else {
		sha256_1_generic(digests, chunks)
	}
}

func HashByteSlice(digests []byte, chunks []byte) error {
	if len(chunks) == 0 {
		return nil
	}

	if len(chunks)%64 != 0 {
		return ErrChunksNotMultipleOf64
	}

	if len(digests)%32 != 0 {
		return ErrDigestsNotMultipleOf32
	}

	if len(digests) < len(chunks)/2 {
		return fmt.Errorf("%w: need at least %v, got %v", ErrNotEnoughDigests, len(chunks)/2, len(digests))
	}
	// We use an unsafe pointer to cast []byte to [][32]byte. The length and
	// capacity of the slice need to be divided accordingly by 32.
	sizeChunks := (len(chunks) >> 5)
	chunkedChunks := unsafe.Slice((*[32]byte)(unsafe.Pointer(&chunks[0])), sizeChunks)

	sizeDigests := (len(digests) >> 5)
	chunkedDigest := unsafe.Slice((*[32]byte)(unsafe.Pointer(&digests[0])), sizeDigests)
	if supportedCPU {
		Hash(chunkedDigest, chunkedChunks)
	} else {
		sha256_1_generic(chunkedDigest, chunkedChunks)
	}
	return nil
}
