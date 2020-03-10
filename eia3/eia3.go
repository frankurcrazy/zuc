package eia3

import (
	"bytes"
	"encoding/binary"
	"github.com/frankurcrazy/zuc"
)

type EIA3 struct {
	zuc *zuc.ZUC
}

func getZi(ks []uint32, i uint32) uint32 {
	zi := uint32(0)

	if ti := i % 32; ti == 0 {
		zi = ks[i/32]
	} else {
		zi = (ks[i/32] << ti) | (ks[i/32+1] >> (32 - ti))
	}

	return zi
}

func NewEIA3(ik []byte, count uint32, bearer uint32, direction zuc.KeyDirection) *EIA3 {
	eia3 := &EIA3{}

	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[:4], count)
	iv[4] = uint8((bearer << 3) & 0xf8)

	binary.BigEndian.PutUint32(iv[8:12], count)
	iv[8] ^= uint8((uint32(direction) & 1) << 7)

	copy(iv[12:16], iv[4:8])
	iv[14] ^= uint8((uint32(direction) & 1) << 7)

	eia3.zuc = zuc.NewZUC(ik, iv)

	return eia3
}

func (e *EIA3) Hash(m []byte, blen uint32) []byte {
	n := blen + 64
	keylength := (n + 31) / 32
	ks := e.zuc.GenerateKeystream(keylength)

	t := uint32(0)
	for i := 0; i < int(blen); i += 1 {
		if m[i/8]&uint8(1<<(7-(i%8))) > 0 {
			t ^= getZi(ks, uint32(i))
		}

	}

	t ^= getZi(ks, blen)

	mac := make([]byte, 4)
	binary.BigEndian.PutUint32(mac, t^ks[keylength-1])

	return mac
}

func (e *EIA3) Verify(m []byte, blen uint32, mac []byte) bool {
	chksum := e.Hash(m, blen)

	return bytes.Compare(chksum, mac) == 0
}
