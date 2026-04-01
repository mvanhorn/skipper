package net

import (
	"bytes"
	"encoding/binary"
)

// PP2_TYPE_SSL is the PROXY protocol v2 TLV type for SSL information
const PP2_TYPE_SSL = 0x20

// ParseProxyProtocolV2Header parses PROXY protocol v2 header to extract SSL information
// Returns true if the header indicates an SSL/TLS connection
func ParseProxyProtocolV2Header(data []byte) bool {
	// Minimum v2 header is 16 bytes
	if len(data) < 16 {
		return false
	}

	// Check for PROXY protocol v2 signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if !bytes.HasPrefix(data, sig) {
		return false
	}

	// Get version from byte 12
	verCmd := data[12]
	version := (verCmd >> 4) & 0x0F

	// We're looking for version 2
	if version != 2 {
		return false
	}

	// Get length of the rest of the header (2 bytes at offset 14-15)
	len16 := binary.BigEndian.Uint16(data[14:16])

	// TLVs start after the 16-byte base header
	tlvStart := 16
	tlvEnd := tlvStart + int(len16)

	// Bounds check
	if tlvEnd > len(data) {
		return false
	}

	// Parse TLVs to find SSL information
	pos := tlvStart
	for pos < tlvEnd {
		// Each TLV has: type (1 byte), length (2 bytes), value (variable)
		if pos+3 > tlvEnd {
			break
		}

		tlvType := data[pos]
		tlvLen := binary.BigEndian.Uint16(data[pos+1 : pos+3])

		// Check for SSL TLV (0x20)
		if tlvType == PP2_TYPE_SSL {
			// SSL TLV found - this indicates TLS connection
			return true
		}

		pos += 3 + int(tlvLen)
	}

	return false
}
