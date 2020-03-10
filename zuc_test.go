package zuc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestZUC(t *testing.T) {
	type TestSet struct {
		Key string
		IV  string
		Z   []string
	}

	testSets := map[string]TestSet{
		"3.3 Test Set 1": TestSet{
			Key: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			IV:  "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
			Z: []string{
				"27bede74",
				"018082da",
			},
		},
		"3.4 Test Set 2": TestSet{
			Key: "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
			IV:  "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
			Z: []string{
				"0657cfa0",
				"7096398b",
			},
		},
		"3.5 Test Set 3": TestSet{
			Key: "3d 4c 4b e9 6a 82 fd ae b5 8f 64 1d b1 7b 45 5b",
			IV:  "84 31 9a a8 de 69 15 ca 1f 6b da 6b fb d8 c7 66",
			Z: []string{
				"14f1c272",
				"3279c419",
			},
		},
		"3.6 Test Set 4": TestSet{
			Key: "4d 32 0b fa d4 c2 85 bf d6 b8 bd 00 f3 9d 8b 41",
			IV:  "52 95 9d ab a0 bf 17 6e ce 2d c3 15 04 9e b5 74",
			Z:   make([]string, 2000),
		},
	}

	testSets["3.6 Test Set 4"].Z[0] = "ed4400e7"
	testSets["3.6 Test Set 4"].Z[1] = "0633e5c5"
	testSets["3.6 Test Set 4"].Z[1999] = "7a574cdb"

	for n, ts := range testSets {
		t.Run(n, func(t *testing.T) {
			key, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Key), ""))
			iv, _ := hex.DecodeString(strings.Join(strings.Fields(ts.IV), ""))

			z := NewZUC(key, iv)
			ks := z.GenerateKeystream(uint32(len(ts.Z)))

			for idx, expected := range ts.Z {
				if len(expected) == 0 {
					continue
				}

				e, _ := hex.DecodeString(expected)
				exp := binary.BigEndian.Uint32(e)

				assert.Equal(t, exp, ks[idx], fmt.Sprintf("Z%d should be equal.", idx+1))
			}
		})
	}
}
