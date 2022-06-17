package aes

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const blockSize = 16

type AES struct {
	enc [][]uint32
	dec [][]uint32
}

func New(key []byte) (cipher.Block, error) {
	switch len(key) {
	default:
		return nil, errors.New("invalid key size")
	case 16, 24, 32:
		break
	}

	l := len(key)/4 + 7
	c := new(AES)
	c.enc = make([][]uint32, l)
	c.dec = make([][]uint32, l)

	for i := 0; i < l; i++ {
		c.enc[i] = make([]uint32, 4)
		c.dec[i] = make([]uint32, 4)
	}

	expandKey(key, c.enc, c.dec)
	return c, nil
}

func (c *AES) BlockSize() int { return blockSize }

func (c *AES) Encrypt(dst, src []byte) {
	_, _ = dst[15], src[15] // bounds check
	b := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		b[i] = binary.BigEndian.Uint32(src[4*i : 4*(i+1)])
	}
	b = encryptBlock(c.enc, b)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(dst[4*i:4*(i+1)], b[i])
	}
}

func (c *AES) Decrypt(dst, src []byte) {
	_, _ = dst[15], src[15] // bounds check
	b := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		b[i] = binary.BigEndian.Uint32(src[4*i : 4*(i+1)])
	}
	b = decryptBlock(c.dec, b)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(dst[4*i:4*(i+1)], b[i])
	}
}

func encryptBlock(xk [][]uint32, b []uint32) []uint32 {
	l := len(xk)

	t := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		t[i] = b[i] ^ xk[0][i]
	}

	for i := 1; i < l-1; i++ {
		for j := 0; j < 4; j++ {
			b[j] = uint32(sBox[t[j]>>24])<<24 | uint32(sBox[t[j]>>16&0xff])<<16 |
				uint32(sBox[t[j]>>8&0xff])<<8 | uint32(sBox[t[j]&0xff])
		}

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		b[0] = t[0]&0xff000000 | t[1]&0xff0000 | t[2]&0xff00 | t[3]&0xff
		b[1] = t[1]&0xff000000 | t[2]&0xff0000 | t[3]&0xff00 | t[0]&0xff
		b[2] = t[2]&0xff000000 | t[3]&0xff0000 | t[0]&0xff00 | t[1]&0xff
		b[3] = t[3]&0xff000000 | t[0]&0xff0000 | t[1]&0xff00 | t[2]&0xff

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		for j := 0; j < 4; j++ {
			b[j] = uint32(mix(0x02, uint8(t[j]>>24))^mix(0x03, uint8(t[j]>>16))^uint8(t[j]>>8)^uint8(t[j]))<<24 |
				uint32(uint8(t[j]>>24)^mix(0x02, uint8(t[j]>>16))^mix(0x03, uint8(t[j]>>8))^uint8(t[j]))<<16 |
				uint32(uint8(t[j]>>24)^uint8(t[j]>>16)^mix(0x02, uint8(t[j]>>8))^mix(0x03, uint8(t[j])))<<8 |
				uint32(mix(0x03, uint8(t[j]>>24))^uint8(t[j]>>16)^uint8(t[j]>>8)^mix(0x02, uint8(t[j])))
		}

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		for j := 0; j < 4; j++ {
			t[j] ^= xk[i][j]
		}
	}

	for j := 0; j < 4; j++ {
		b[j] = uint32(sBox[t[j]>>24])<<24 | uint32(sBox[t[j]>>16&0xff])<<16 |
			uint32(sBox[t[j]>>8&0xff])<<8 | uint32(sBox[t[j]&0xff])
	}

	t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

	b[0] = t[0]&0xff000000 | t[1]&0xff0000 | t[2]&0xff00 | t[3]&0xff
	b[1] = t[1]&0xff000000 | t[2]&0xff0000 | t[3]&0xff00 | t[0]&0xff
	b[2] = t[2]&0xff000000 | t[3]&0xff0000 | t[0]&0xff00 | t[1]&0xff
	b[3] = t[3]&0xff000000 | t[0]&0xff0000 | t[1]&0xff00 | t[2]&0xff

	for j := 0; j < 4; j++ {
		b[j] ^= xk[l-1][j]
	}

	return b
}

func decryptBlock(xk [][]uint32, b []uint32) []uint32 {
	l := len(xk)

	t := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		t[i] = b[i] ^ xk[0][i]
	}

	for i := 1; i < l-1; i++ {
		for j := 0; j < 4; j++ {
			b[j] = uint32(inverseSBox[t[j]>>24])<<24 | uint32(inverseSBox[t[j]>>16&0xff])<<16 |
				uint32(inverseSBox[t[j]>>8&0xff])<<8 | uint32(inverseSBox[t[j]&0xff])
		}

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		b[0] = t[0]&0xff000000 | t[3]&0xff0000 | t[2]&0xff00 | t[1]&0xff
		b[1] = t[1]&0xff000000 | t[0]&0xff0000 | t[3]&0xff00 | t[2]&0xff
		b[2] = t[2]&0xff000000 | t[1]&0xff0000 | t[0]&0xff00 | t[3]&0xff
		b[3] = t[3]&0xff000000 | t[2]&0xff0000 | t[1]&0xff00 | t[0]&0xff

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		for j := 0; j < 4; j++ {
			b[j] = uint32(mix(14, uint8(t[j]>>24))^mix(11, uint8(t[j]>>16))^
				mix(13, uint8(t[j]>>8))^mix(9, uint8(t[j])))<<24 |
				uint32(mix(9, uint8(t[j]>>24))^mix(14, uint8(t[j]>>16))^
					mix(11, uint8(t[j]>>8))^mix(13, uint8(t[j])))<<16 |
				uint32(mix(13, uint8(t[j]>>24))^mix(9, uint8(t[j]>>16))^
					mix(14, uint8(t[j]>>8))^mix(11, uint8(t[j])))<<8 |
				uint32(mix(11, uint8(t[j]>>24))^mix(13, uint8(t[j]>>16))^
					mix(9, uint8(t[j]>>8))^mix(14, uint8(t[j])))
		}

		t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

		for j := 0; j < 4; j++ {
			t[j] ^= xk[i][j]
		}
	}

	for j := 0; j < 4; j++ {
		b[j] = uint32(inverseSBox[t[j]>>24])<<24 | uint32(inverseSBox[t[j]>>16&0xff])<<16 |
			uint32(inverseSBox[t[j]>>8&0xff])<<8 | uint32(inverseSBox[t[j]&0xff])
	}

	t[0], t[1], t[2], t[3] = b[0], b[1], b[2], b[3]

	b[0] = t[0]&0xff000000 | t[3]&0xff0000 | t[2]&0xff00 | t[1]&0xff
	b[1] = t[1]&0xff000000 | t[0]&0xff0000 | t[3]&0xff00 | t[2]&0xff
	b[2] = t[2]&0xff000000 | t[1]&0xff0000 | t[0]&0xff00 | t[3]&0xff
	b[3] = t[3]&0xff000000 | t[2]&0xff0000 | t[1]&0xff00 | t[0]&0xff

	for j := 0; j < 4; j++ {
		b[j] ^= xk[l-1][j]
	}

	return b
}

func mix(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		if (b & 0x01) != 0 {
			p ^= a
		}
		if (a & 0x80) != 0 {
			a <<= 1
			a ^= 0x1b
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return p
}

var rcon = [16]byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
}

func expandKey(key []byte, enc, dec [][]uint32) {
	nk := len(key) / 4
	for i := 0; i < nk; i++ {
		enc[i/4][i%4] = binary.BigEndian.Uint32(key[4*i:])
	}
	for i := nk; i < len(enc)*4; i++ {
		g := enc[(i-1)/4][(i-1)%4]
		if i%nk == 0 {
			g = g<<8 | g>>24
		}
		if i%nk == 0 || (nk > 6 && i%nk == 4) {
			g = uint32(sBox[g>>24])<<24 | uint32(sBox[g>>16&0xff])<<16 | uint32(sBox[g>>8&0xff])<<8 | uint32(sBox[g&0xff])
		}
		if i%nk == 0 {
			g ^= uint32(rcon[i/nk-1]) << 24
		}
		enc[i/4][i%4] = enc[(i-nk)/4][(i-nk)%4] ^ g
	}

	if dec == nil {
		return
	}
	n := len(enc)
	for i := 0; i < n; i++ {
		for j := 0; j < 4; j++ {
			t := enc[n-i-1][j]
			if i > 0 && i < n-1 {
				t = uint32(mix(14, uint8(t>>24))^mix(11, uint8(t>>16))^
					mix(13, uint8(t>>8))^mix(9, uint8(t)))<<24 |
					uint32(mix(9, uint8(t>>24))^mix(14, uint8(t>>16))^
						mix(11, uint8(t>>8))^mix(13, uint8(t)))<<16 |
					uint32(mix(13, uint8(t>>24))^mix(9, uint8(t>>16))^
						mix(14, uint8(t>>8))^mix(11, uint8(t)))<<8 |
					uint32(mix(11, uint8(t>>24))^mix(13, uint8(t>>16))^
						mix(9, uint8(t>>8))^mix(14, uint8(t)))
			}
			dec[i][j] = t
		}
	}
}
