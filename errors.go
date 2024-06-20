package gohashtree

import "errors"

var (
	// ErrOddChunks is returned when the number of chunks is odd.
	ErrOddChunks = errors.New("odd number of chunks")
	// ErrNotEnoughDigests is returned when the number of digests is not enough.
	ErrNotEnoughDigests = errors.New("not enough digest length")
	// ErrNotMultipleOf64 is returned when the chunks are not multiple of 64 bytes.
	ErrNotMultipleOf64 = errors.New("chunks not multiple of 64 bytes")
	// ErrNotMultipleOf32 is returned when the digests are not multiple of 32 bytes.
	ErrNotMultipleOf32 = errors.New("digests not multiple of 32 bytes")
)
