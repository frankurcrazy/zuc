// code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3.
// Document 1: 128-EEA3 and 128-EIA3 Specification. Version 1.7 from the 30th December 2011, annex 1.
// https://www.gsma.com/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf

package eea3

import (
	"encoding/binary"
	"github.com/frankurcrazy/zuc"
)

type EEA3 struct {
	zuc *zuc.ZUC
}

func NewEEA3(ck []byte, count uint32, bearer uint32, direction zuc.KeyDirection) *EEA3 {
	eea3 := &EEA3{}

	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[:4], count)

	iv[4] = uint8((bearer << 3) | ((uint32(direction)&1)<<2)&0xfc)
	copy(iv[8:12], iv[:4])
	copy(iv[12:16], iv[4:8])

	eea3.zuc = zuc.NewZUC(ck, iv)

	return eea3
}

func (e *EEA3) Encrypt(m []byte, blength uint32) []byte {
	zeroBits := blength & 0x7
	keylength := (blength + 31) / 32
	length := blength >> 3

	if zeroBits > 0 {
		length += 1
	}

	ks := e.zuc.GenerateKeystream(keylength)
	output := make([]byte, len(m))

	for i := 0; i < int(keylength); i += 1 {
		for j := 0; j < 4 && i*4+j < int(length); j += 1 {
			output[4*i+j] = m[4*i+j] ^ uint8((ks[i]>>(8*(3-j)))&0xff)
		}
	}

	if zeroBits > 0 {
		output[length-1] = output[length-1] & (uint8(0xff) << (8 - zeroBits))
	}

	for j := int(length); j < len(output); j += 1 {
		output[j] = 0
	}

	return output
}

func (e *EEA3) Decrypt(m []byte, blength uint32) []byte {
	return e.Encrypt(m, blength)
}
