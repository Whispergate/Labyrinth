package crypto

func Decrypt(enc, key []byte) []byte {
	out := make([]byte, len(enc))
	copy(out, enc)
	for i := range out {
		out[i] ^= key[i%len(key)]
	}
	return out
}

func Wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
