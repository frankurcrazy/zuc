// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3.
// Document 2: ZUC Specification. Version 1.6 from 28th June 2011, appendix A.
// https://www.gsma.com/security/wp-content/uploads/2019/05/eea3eia3zucv16.pdf

package zuc

type BRC struct {
	X0 uint32
	X1 uint32
	X2 uint32
	X3 uint32
}

type LFSR struct {
	S0  uint32
	S1  uint32
	S2  uint32
	S3  uint32
	S4  uint32
	S5  uint32
	S6  uint32
	S7  uint32
	S8  uint32
	S9  uint32
	S10 uint32
	S11 uint32
	S12 uint32
	S13 uint32
	S14 uint32
	S15 uint32
}

type F struct {
	R1 uint32
	R2 uint32
}

type ZUC struct {
	lfsr           *LFSR
	brc            *BRC
	f              *F
	is_initialized bool
	is_first       bool
}

func (lfsr *LFSR) update(f uint32) {
	lfsr.S0 = lfsr.S1
	lfsr.S1 = lfsr.S2
	lfsr.S2 = lfsr.S3
	lfsr.S3 = lfsr.S4
	lfsr.S4 = lfsr.S5
	lfsr.S5 = lfsr.S6
	lfsr.S6 = lfsr.S7
	lfsr.S7 = lfsr.S8
	lfsr.S8 = lfsr.S9
	lfsr.S9 = lfsr.S10
	lfsr.S10 = lfsr.S11
	lfsr.S11 = lfsr.S12
	lfsr.S12 = lfsr.S13
	lfsr.S13 = lfsr.S14
	lfsr.S14 = lfsr.S15
	lfsr.S15 = f
}

func (lfsr *LFSR) WithInitialisationMode(u uint32) {
	f := lfsr.S0

	v := mulByPow2(lfsr.S0, 8)
	f = addM(f, v)

	v = mulByPow2(lfsr.S4, 20)
	f = addM(f, v)

	v = mulByPow2(lfsr.S10, 21)
	f = addM(f, v)

	v = mulByPow2(lfsr.S13, 17)
	f = addM(f, v)

	v = mulByPow2(lfsr.S15, 15)
	f = addM(f, v)

	f = addM(f, u)

	lfsr.update(f)
}

func (lfsr *LFSR) WithWorkMode() {
	f := lfsr.S0

	v := mulByPow2(lfsr.S0, 8)
	f = addM(f, v)

	v = mulByPow2(lfsr.S4, 20)
	f = addM(f, v)

	v = mulByPow2(lfsr.S10, 21)
	f = addM(f, v)

	v = mulByPow2(lfsr.S13, 17)
	f = addM(f, v)

	v = mulByPow2(lfsr.S15, 15)
	f = addM(f, v)

	lfsr.update(f)
}

func (z *ZUC) bitReorganization() {
	z.brc.X0 = ((z.lfsr.S15 & 0x7FFF8000) << 1) | (z.lfsr.S14 & 0xFFFF)
	z.brc.X1 = ((z.lfsr.S11 & 0xFFFF) << 16) | (z.lfsr.S9 >> 15)
	z.brc.X2 = ((z.lfsr.S7 & 0xFFFF) << 16) | (z.lfsr.S5 >> 15)
	z.brc.X3 = ((z.lfsr.S2 & 0xFFFF) << 16) | (z.lfsr.S0 >> 15)
}

func (z *ZUC) f_() uint32 {
	w := (z.brc.X0 ^ z.f.R1) + z.f.R2
	w1 := (z.f.R1 + z.brc.X1)
	w2 := (z.f.R2 ^ z.brc.X2)

	u := l1((w1 << 16) | (w2 >> 16))
	v := l2((w2 << 16) | (w1 >> 16))

	z.f.R1 = makeU32(S0[u>>24], S1[(u>>16)&0xff],
		S0[(u>>8)&0xff], S1[u&0xff])
	z.f.R2 = makeU32(S0[v>>24], S1[(v>>16)&0xff],
		S0[(v>>8)&0xff], S1[v&0xff])

	return w
}

func (z *ZUC) Initialization(k []uint8, iv []uint8) {
	if z.lfsr == nil {
		z.lfsr = &LFSR{}
	}

	if z.f == nil {
		z.f = &F{}
	}

	if z.brc == nil {
		z.brc = &BRC{}
	}

	z.is_first = true

	z.lfsr.S0 = makeU31(uint32(k[0]), uint32(D[0]), uint32(iv[0]))
	z.lfsr.S1 = makeU31(uint32(k[1]), uint32(D[1]), uint32(iv[1]))
	z.lfsr.S2 = makeU31(uint32(k[2]), uint32(D[2]), uint32(iv[2]))
	z.lfsr.S3 = makeU31(uint32(k[3]), uint32(D[3]), uint32(iv[3]))
	z.lfsr.S4 = makeU31(uint32(k[4]), uint32(D[4]), uint32(iv[4]))
	z.lfsr.S5 = makeU31(uint32(k[5]), uint32(D[5]), uint32(iv[5]))
	z.lfsr.S6 = makeU31(uint32(k[6]), uint32(D[6]), uint32(iv[6]))
	z.lfsr.S7 = makeU31(uint32(k[7]), uint32(D[7]), uint32(iv[7]))
	z.lfsr.S8 = makeU31(uint32(k[8]), uint32(D[8]), uint32(iv[8]))
	z.lfsr.S9 = makeU31(uint32(k[9]), uint32(D[9]), uint32(iv[9]))
	z.lfsr.S10 = makeU31(uint32(k[10]), uint32(D[10]), uint32(iv[10]))
	z.lfsr.S11 = makeU31(uint32(k[11]), uint32(D[11]), uint32(iv[11]))
	z.lfsr.S12 = makeU31(uint32(k[12]), uint32(D[12]), uint32(iv[12]))
	z.lfsr.S13 = makeU31(uint32(k[13]), uint32(D[13]), uint32(iv[13]))
	z.lfsr.S14 = makeU31(uint32(k[14]), uint32(D[14]), uint32(iv[14]))
	z.lfsr.S15 = makeU31(uint32(k[15]), uint32(D[15]), uint32(iv[15]))

	z.f.R1 = 0
	z.f.R2 = 0

	for n := 32; n > 0; n -= 1 {
		z.bitReorganization()
		w := z.f_()
		z.lfsr.WithInitialisationMode(w >> 1)
	}

	if !z.is_initialized {
		z.is_initialized = true
	}
}

func (z *ZUC) GenerateKeystream(length uint32) []uint32 {
	keys := []uint32{}

	for i := uint32(0); i < length; i += 1 {
		keys = append(keys, z.NextKey())
	}

	return keys
}

func (z *ZUC) NextKey() uint32 {
	if !z.is_initialized {
		panic("ZUC not initialized.")
	}

	if z.is_first {
		z.bitReorganization()
		z.f_()
		z.lfsr.WithWorkMode()
		z.is_first = false
	}

	z.bitReorganization()
	k := z.f_() ^ z.brc.X3
	z.lfsr.WithWorkMode()

	return k
}

func NewZUC(k []uint8, iv []uint8) *ZUC {
	zuc := &ZUC{}
	zuc.Initialization(k, iv)

	return zuc
}
