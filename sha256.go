/*
MIT License

Copyright (c) 2021 Prysmatic Labs

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
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha256 implements the SHA224 and SHA256 hash algorithms as defined
// in FIPS 180-4.
package gohashtree

// The size of a SHA256 checksum in bytes.
const DigestSize = 32

// The blocksize of SHA256 and SHA224 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = uint32(0x6A09E667)
	init1 = uint32(0xBB67AE85)
	init2 = uint32(0x3C6EF372)
	init3 = uint32(0xA54FF53A)
	init4 = uint32(0x510E527F)
	init5 = uint32(0x9B05688C)
	init6 = uint32(0x1F83D9AB)
	init7 = uint32(0x5BE0CD19)
)

type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}
