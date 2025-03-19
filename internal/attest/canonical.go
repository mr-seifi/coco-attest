package attest

import (
	"bytes"
	"encoding/binary"
)

func CanonicalReport(e *Evidence) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(e.TEEType))
	writeField(&b, []byte(e.Nonce))
	writeField(&b, []byte(e.Measurement))
	writeField(&b, []byte(e.ReportData))
	writeField(&b, e.PublicKey)
	return b.Bytes()
}

func writeField(b *bytes.Buffer, field []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	b.Write(l[:])
	b.Write(field)
}
