package eia3

import (
	"encoding/hex"
	"github.com/frankurcrazy/zuc"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestEIA3(t *testing.T) {
	type TestSet struct {
		Key       string
		Count     uint32
		Bearer    uint32
		Direction zuc.KeyDirection
		BitLength uint32
		Message   string
		MAC       string
	}

	testSets := map[string]TestSet{
		"5.2 Test Set 1": TestSet{
			Key:       "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			Count:     0x00,
			Bearer:    0x00,
			Direction: zuc.KEY_UPLINK,
			BitLength: 1,
			Message:   "00000000",
			MAC:       "c8a9595e",
		},
		"5.3 Test Set 2": TestSet{
			Key:       "47 05 41 25 56 1e b2 dd a9 40 59 da 05 09 78 50",
			Count:     0x561eb2dd,
			Bearer:    0x14,
			Direction: zuc.KEY_UPLINK,
			BitLength: 90,
			Message:   "00000000 00000000 00000000",
			MAC:       "6719a088",
		},
		"5.4 Test Set 3": TestSet{
			Key:       "c9 e6 ce c4 60 7c 72 db 00 0a ef a8 83 85 ab 0a",
			Count:     0xa94059da,
			Bearer:    0x0a,
			Direction: zuc.KEY_DOWNLINK,
			BitLength: 577,
			Message: `983b41d4 7d780c9e 1ad11d7e b70391b1 de0b35da 2dc62f83 e7b78d63 06ca0ea0
                        7e941b7b e91348f9 fcb170e2 217fecd9 7f9f68ad b16e5d7d 21e569d2 80ed775c
                        ebde3f40 93c53881 00000000`,
			MAC: "fae8ff0b",
		},
		"5.5 Test Set 4": TestSet{
			Key:       "c8 a4 82 62 d0 c2 e2 ba c4 b9 6e f7 7e 80 ca 59",
			Count:     0x05097850,
			Bearer:    0x10,
			Direction: zuc.KEY_DOWNLINK,
			BitLength: 2079,
			Message: `b546430b f87b4f1e e834704c d6951c36 e26f108c f731788f 48dc34f1 678c0522
                        1c8fa7ff 2f39f477 e7e49ef6 0a4ec2c3 de24312a 96aa26e1 cfba5756 3838b297
                        f47e8510 c779fd66 54b14338 6fa639d3 1edbd6c0 6e47d159 d94362f2 6aeeedee
                        0e4f49d9 bf841299 5415bfad 56ee82d1 ca7463ab f085b082 b09904d6 d990d43c
                        f2e062f4 0839d932 48b1eb92 cdfed530 0bc14828 0430b6d0 caa094b6 ec8911ab
                        7dc36824 b824dc0a f6682b09 35fde7b4 92a14dc2 f4364803 8da2cf79 170d2d50
                        133fd494 16cb6e33 bea90b8b f4559b03 732a01ea 290e6d07 4f79bb83 c10e5800
                        15cc1a85 b36b5501 046e9c4b dcae5135 690b8666 bd54b7a7 03ea7b6f 220a5469
                        a568027e`,
			MAC: "004ac4d6",
		},
		"5.6 Test Set 5": TestSet{
			Key:       "6b 8b 08 ee 79 e0 b5 98 2d 6d 12 8e a9 f2 20 cb",
			Count:     0x561eb2dd,
			Bearer:    0x1c,
			Direction: zuc.KEY_UPLINK,
			BitLength: 5670,
			Message: `5bad7247 10ba1c56 d5a315f8 d40f6e09 3780be8e 8de07b69 92432018 e08ed96a
                        5734af8b ad8a575d 3a1f162f 85045cc7 70925571 d9f5b94e 454a77c1 6e72936b
                        f016ae15 7499f054 3b5d52ca a6dbeab6 97d2bb73 e41b8075 dce79b4b 86044f66
                        1d4485a5 43dd7860 6e0419e8 059859d3 cb2b67ce 0977603f 81ff839e 33185954
                        4cfbc8d0 0fef1a4c 8510fb54 7d6b06c6 11ef44f1 bce107cf a45a06aa b360152b
                        28dc1ebe 6f7fe09b 0516f9a5 b02a1bd8 4bb0181e 2e89e19b d8125930 d178682f
                        3862dc51 b636f04e 720c47c3 ce51ad70 d94b9b22 55fbae90 6549f499 f8c6d399
                        47ed5e5d f8e2def1 13253e7b 08d0a76b 6bfc68c8 12f375c7 9b8fe5fd 85976aa6
                        d46b4a23 39d8ae51 47f680fb e70f978b 38effd7b 2f7866a2 2554e193 a94e98a6
                        8b74bd25 bb2b3f5f b0a5fd59 887f9ab6 8159b717 8d5b7b67 7cb546bf 41eadca2
                        16fc1085 0128f8bd ef5c8d89 f96afa4f a8b54885 565ed838 a950fee5 f1c3b0a4
                        f6fb71e5 4dfd169e 82cecc72 66c850e6 7c5ef0ba 960f5214 060e71eb 172a75fc
                        1486835c bea65344 65b055c9 6a72e410 52241823 25d83041 4b40214d aa8091d2
                        e0fb010a e15c6de9 0850973b df1e423b e148a237 b87a0c9f 34d4b476 05b803d7
                        43a86a90 399a4af3 96d3a120 0a62f3d9 507962e8 e5bee6d3 da2bb3f7 237664ac
                        7a292823 900bc635 03b29e80 d63f6067 bf8e1716 ac25beba 350deb62 a99fe031
                        85eb4f69 937ecd38 7941fda5 44ba67db 09117749 38b01827 bcc69c92 b3f772a9
                        d2859ef0 03398b1f 6bbad7b5 74f7989a 1d10b2df 798e0dbf 30d65874 64d24878
                        cd00c0ea ee8a1a0c c753a279 79e11b41 db1de3d5 038afaf4 9f5c682c 3748d8a3
                        a9ec54e6 a371275f 1683510f 8e4f9093 8f9ab6e1 34c2cfdf 4841cba8 8e0cff2b
                        0bcc8e6a dcb71109 b5198fec f1bb7e5c 531aca50 a56a8a3b 6de59862 d41fa113
                        d9cd9578 08f08571 d9a4bb79 2af271f6 cc6dbb8d c7ec36e3 6be1ed30 8164c31c
                        7c0afc54 1c000000`,
			MAC: "0ca12792",
		},
	}

	for n, ts := range testSets {
		t.Run(n, func(t *testing.T) {
			key, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Key), ""))
			count := ts.Count
			bearer := ts.Bearer
			direction := ts.Direction
			blen := ts.BitLength
			msg, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Message), ""))
			mac, _ := hex.DecodeString(ts.MAC)

			eia3 := NewEIA3(key, count, bearer, direction)
			result := eia3.Hash(msg, blen)

			assert.Equal(t, mac, result, "MAC mismatched!")
		})
	}
}
