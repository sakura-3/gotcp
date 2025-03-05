package ip

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestIPString(t *testing.T) {
	ip := IP{192, 168, 1, 1}
	expected := "192.168.1.1"
	if ip.String() != expected {
		t.Errorf("expected %s, got %s", expected, ip.String())
	}
}

func TestFlagsDF(t *testing.T) {
	var f Flags = 0b010
	if !f.DF() {
		t.Errorf("expected DF to be true, got false, flags = 0b%b", f)
	}
	f = 0b000
	if f.DF() {
		t.Errorf("expected DF to be false, got true, flags = 0b%b", f)
	}
}

func TestFlagsMF(t *testing.T) {
	var f Flags = 0b001
	if !f.MF() {
		t.Errorf("expected MF to be true, got false")
	}
	f = 0b000
	if f.MF() {
		t.Errorf("expected MF to be false, got true")
	}
}

// ping 10.1.0.20
func TestNewIPPacket_ICMP(t *testing.T) {
	hexData := "45 00 00 54 32 2c 00 00 40 01 34 5e 0a 01 00 0a 0a 01 00 14 08 00 80 20 61 48 00 00 67 c5 10 7f 00 0b b3 44 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37"
	hexData = string(bytes.ReplaceAll([]byte(hexData), []byte(" "), []byte("")))
	rawData, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}

	packet, err := NewIPPacketFromLower(rawData)
	if err != nil {
		t.Error(err)
	}

	if packet.Version != 4 {
		t.Errorf("Expected version 4, got %d", packet.Version)
	}
	if packet.IHL != 20 {
		t.Errorf("Expected IHL 4 * 5, got %d", packet.IHL)
	}
	if packet.Tos != 0 {
		t.Errorf("Expected Tos 0, got %d", packet.Tos)
	}
	if packet.TotLen != 84 {
		t.Errorf("Expected TotLen 84, got %d", packet.TotLen)
	}
	if packet.ID != 0x322c {
		t.Errorf("Expected ID 0x322c, got %x", packet.ID)
	}
	if packet.Flags != 0 {
		t.Errorf("Expected Flags 0, got %d", packet.Flags)
	}
	if packet.Offset != 0 {
		t.Errorf("Expected Offset 0, got %d", packet.Offset)
	}
	if packet.TTL != 64 {
		t.Errorf("Expected TTL 64, got %d", packet.TTL)
	}
	if packet.Proto != 1 {
		t.Errorf("Expected Proto 1 (ICMP), got %d", packet.Proto)
	}
	if packet.Checksum != 0x345e {
		t.Errorf("Expected Checksum 0x345e, got %x", packet.Checksum)
	}
	if !bytes.Equal(packet.SrcIp[:], []byte{0x0a, 0x01, 0x00, 0x0a}) {
		t.Errorf("Expected SrcIp 10.1.0.10, got %s", packet.SrcIp)
	}
	if !bytes.Equal(packet.DstIp[:], []byte{0x0a, 0x01, 0x00, 0x14}) {
		t.Errorf("Expected DstIp 10.1.0.20, got %s", packet.DstIp)
	}
	if len(packet.Options) != 0 {
		t.Errorf("Expected no options, got %v", packet.Options)
	}
	if len(packet.Payload) != 64 {
		t.Errorf("Expected Payload length 64, got %d", len(packet.Payload))
	}
}

// nc
func TestNewIPPacket_TCP(t *testing.T) {
	hexData := "45 00 00 40 00 00 40 00 40 06 26 99 0a 01 00 0a 0a 01 00 14 ce cc 1f 90 66 e6 2e ab 00 00 00 00 b0 02 ff ff 0c 51 00 00 02 04 05 b4 01 03 03 06 01 01 08 0a 16 85 7c 18 00 00 00 00 04 02 00 00"
	hexData = string(bytes.ReplaceAll([]byte(hexData), []byte(" "), []byte("")))
	rawData, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}

	packet, err := NewIPPacketFromLower(rawData)
	if err != nil {
		t.Error(err)
	}

	if packet.Version != 4 {
		t.Errorf("Expected version 4, got %d", packet.Version)
	}

	if packet.IHL != 20 {
		t.Errorf("Expected IHL 20, got %d", packet.IHL)
	}

	if packet.Tos != 0 {
		t.Errorf("Expected Tos 0, got %d", packet.Tos)
	}

	if packet.TotLen != 64 {
		t.Errorf("Expected TotLen 64, got %d", packet.TotLen)
	}

	if packet.ID != 0 {
		t.Errorf("Expected ID 0, got %x", packet.ID)
	}

	if packet.Flags != 2 {
		t.Errorf("Expected Flags 2, got %d", packet.Flags)
	}

	if packet.Offset != 0 {
		t.Errorf("Expected Offset 0, got %d", packet.Offset)
	}

	if packet.TTL != 64 {
		t.Errorf("Expected TTL 64, got %d", packet.TTL)
	}

	if packet.Proto != 6 {
		t.Errorf("Expected Proto 6 (TCP), got %d", packet.Proto)
	}

	if packet.Checksum != 0x2699 {
		t.Errorf("Expected Checksum 0x2699, got %x", packet.Checksum)
	}

	expectedSrcIp := []byte{0x0a, 0x01, 0x00, 0x0a}
	if !bytes.Equal(packet.SrcIp[:], expectedSrcIp) {
		t.Errorf("Expected SrcIp 10.1.0.10, got %v", packet.SrcIp)
	}

	expectedDstIp := []byte{0x0a, 0x01, 0x00, 0x14}
	if !bytes.Equal(packet.DstIp[:], expectedDstIp) {
		t.Errorf("Expected DstIp 10.1.0.20, got %v", packet.DstIp)
	}

	if len(packet.Options) != 0 {
		t.Errorf("Expected no options, got %v", packet.Options)
	}

	if len(packet.Payload) != 44 {
		t.Errorf("Expected Payload length 44, got %d", len(packet.Payload))
	}
}

func TestByte(t *testing.T) {
	hexData := "45 00 00 40 00 00 40 00 40 06 26 99 0a 01 00 0a 0a 01 00 14 ce cc 1f 90 66 e6 2e ab 00 00 00 00 b0 02 ff ff 0c 51 00 00 02 04 05 b4 01 03 03 06 01 01 08 0a 16 85 7c 18 00 00 00 00 04 02 00 00"
	hexData = string(bytes.ReplaceAll([]byte(hexData), []byte(" "), []byte("")))
	rawData, err := hex.DecodeString(hexData)
	if err != nil {
		t.Error(err)
	}

	packet, err := NewIPPacketFromLower(rawData)
	if err != nil {
		t.Error(err)
	}
	byteData := packet.HeaderByte()
	byteData = append(byteData, packet.Payload...)
	if len(byteData) != len(rawData) {
		t.Errorf("Expected byteData length %d, got %d", len(rawData), len(byteData))
	}

	for i := range byteData {
		if byteData[i] != rawData[i] {
			t.Errorf("Expected byteData[%d] = %x, got %x", i, rawData[i], byteData[i])
		}
	}
}
