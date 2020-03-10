// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3.
// Document 2: ZUC Specification. Version 1.6 from 28th June 2011, appendix A.
// https://www.gsma.com/security/wp-content/uploads/2019/05/eea3eia3zucv16.pdf

package zuc

type KeyDirection uint32

const (
	KEY_UPLINK   = KeyDirection(0)
	KEY_DOWNLINK = KeyDirection(1)
)

func addM(a uint32, b uint32) uint32 {
	c := a + b

	return (c & 0x7fffffff) + (c >> 31)
}

func mulByPow2(x uint32, k uint8) uint32 {
	return ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF
}

func rot(a uint32, k uint8) uint32 {
	return ((a) << k) | ((a) >> (32 - k))
}

func makeU32(a, b, c, d uint8) uint32 {
	return ((uint32(a) << 24) | (uint32(b) << 16) | (uint32(c) << 8) | (uint32(d)))
}

func makeU31(a, b, c uint32) uint32 {
	return ((a << 23) | (b << 8) | (c))
}

func l1(x uint32) uint32 {
	return (x ^ rot(x, 2) ^ rot(x, 10) ^ rot(x, 18) ^ rot(x, 24))
}

func l2(x uint32) uint32 {
	return (x ^ rot(x, 8) ^ rot(x, 14) ^ rot(x, 22) ^ rot(x, 30))
}
