// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

// TLSHandshakeType 定义 TLS 握手消息类型
type TLSHandshakeType uint8

const (
	HandshakeTypeHelloRequest       TLSHandshakeType = 0
	HandshakeTypeClientHello        TLSHandshakeType = 1
	HandshakeTypeServerHello        TLSHandshakeType = 2
	HandshakeTypeNewSessionTicket   TLSHandshakeType = 4
	HandshakeTypeCertificate        TLSHandshakeType = 11
	HandshakeTypeServerKeyExchange  TLSHandshakeType = 12
	HandshakeTypeCertificateRequest TLSHandshakeType = 13
	HandshakeTypeServerHelloDone    TLSHandshakeType = 14
	HandshakeTypeCertificateVerify  TLSHandshakeType = 15
	HandshakeTypeClientKeyExchange  TLSHandshakeType = 16
	HandshakeTypeFinished           TLSHandshakeType = 20
)

// TLSHandshakeRecord 定义 TLS 握手记录结构
type TLSHandshakeRecord struct {
	TLSRecordHeader
	HandshakeMessages []TLSHandshakeMessage
}

// TLSHandshakeMessage 握手消息接口
type TLSHandshakeMessage interface {
	Type() TLSHandshakeType
	Length() int
	String() string
}

// TLSHandshakeGeneric 通用握手消息结构（用于未实现的消息类型）
type TLSHandshakeGeneric struct {
	MsgType TLSHandshakeType
	Data    []byte
}

func (m *TLSHandshakeGeneric) Type() TLSHandshakeType { return m.MsgType }
func (m *TLSHandshakeGeneric) Length() int            { return len(m.Data) }
func (m *TLSHandshakeGeneric) String() string {
	return fmt.Sprintf("%s (%d bytes)", m.MsgType, len(m.Data))
}

// TLSClientHello 定义 ClientHello 消息结构
type TLSClientHello struct {
	Version            TLSVersion
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []TLSExtension
}

func (m *TLSClientHello) Type() TLSHandshakeType { return HandshakeTypeClientHello }
func (m *TLSClientHello) Length() int {
	length := 34 + len(m.SessionID) + 2 + len(m.CipherSuites)*2 + 1 + len(m.CompressionMethods)
	for _, ext := range m.Extensions {
		length += 4 + len(ext.Data)
	}
	return length
}
func (m *TLSClientHello) String() string {
	return fmt.Sprintf("ClientHello: Version=%s, CipherSuites=%d, Extensions=%d",
		m.Version, len(m.CipherSuites), len(m.Extensions))
}

// TLSServerHello 定义 ServerHello 消息结构
type TLSServerHello struct {
	Version           TLSVersion
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	Extensions        []TLSExtension
}

func (m *TLSServerHello) Type() TLSHandshakeType { return HandshakeTypeServerHello }
func (m *TLSServerHello) Length() int {
	length := 34 + len(m.SessionID) + 2 + 1
	for _, ext := range m.Extensions {
		length += 4 + len(ext.Data)
	}
	return length
}
func (m *TLSServerHello) String() string {
	return fmt.Sprintf("ServerHello: Version=%s, CipherSuite=0x%04x",
		m.Version, m.CipherSuite)
}

// TLSCertificate 定义 Certificate 消息结构
type TLSCertificate struct {
	Certificates [][]byte // ASN.1 DER 格式的证书链
}

func (m *TLSCertificate) Type() TLSHandshakeType { return HandshakeTypeCertificate }
func (m *TLSCertificate) Length() int {
	length := 3 // 证书链长度字段
	for _, cert := range m.Certificates {
		length += 3 + len(cert)
	}
	return length
}
func (m *TLSCertificate) String() string {
	return fmt.Sprintf("Certificate: Certificates=%d", len(m.Certificates))
}

const (
	TLSExtensionServerName          uint16 = 0
	TLSExtensionStatusRequest       uint16 = 5
	TLSExtensionSupportedCurves     uint16 = 10
	TLSExtensionSupportedPoints     uint16 = 11
	TLSExtensionSignatureAlgorithms uint16 = 13
	TLSExtensionALPN                uint16 = 16
	TLSExtensionSCT                 uint16 = 18
	TLSExtensionSessionTicket       uint16 = 35
	TLSExtensionPreSharedKey        uint16 = 41
	TLSExtensionEarlyData           uint16 = 42
	TLSExtensionSupportedVersions   uint16 = 43
	TLSExtensionPSKKeyExchangeModes uint16 = 45
	TLSExtensionKeyShare            uint16 = 51
)

// TLSExtension 定义 TLS 扩展结构
type TLSExtension struct {
	Type uint16
	Data []byte
}

// DecodeFromBytes 解码 TLS 握手记录
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS 记录头
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	// 重置消息切片
	t.HandshakeMessages = t.HandshakeMessages[:0]

	// 解析握手消息
	offset := 0
	for offset < len(data) {
		if len(data[offset:]) < 4 {
			df.SetTruncated()
			return errors.New("TLS handshake message too short")
		}

		// 解析握手消息头
		msgType := TLSHandshakeType(data[offset])
		offset++

		// 读取消息长度 (3字节大端序)
		msgLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+msgLen > len(data) {
			df.SetTruncated()
			return fmt.Errorf("TLS handshake message length exceeds data: %d > %d",
				offset+msgLen, len(data))
		}

		msgData := data[offset : offset+msgLen]
		offset += msgLen

		// 根据消息类型解析具体内容
		var msg TLSHandshakeMessage
		var err error

		switch msgType {
		case HandshakeTypeClientHello:
			msg, err = decodeClientHello(msgData)
		case HandshakeTypeServerHello:
			msg, err = decodeServerHello(msgData)
		case HandshakeTypeCertificate:
			msg, err = decodeCertificate(msgData)
		default:
			// 对于不支持的消息类型，使用通用结构
			msg = &TLSHandshakeGeneric{
				MsgType: msgType,
				Data:    msgData,
			}
		}

		if err != nil {
			return fmt.Errorf("error decoding %s: %v", msgType, err)
		}

		t.HandshakeMessages = append(t.HandshakeMessages, msg)
	}

	return nil
}

// decodeClientHello 解析 ClientHello 消息
func decodeClientHello(data []byte) (*TLSClientHello, error) {
	msg := &TLSClientHello{}
	offset := 0

	// 版本 (2字节)
	if len(data) < 34 {
		return nil, errors.New("ClientHello too short")
	}
	msg.Version = TLSVersion(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// 随机数 (32字节)
	copy(msg.Random[:], data[offset:offset+32])
	offset += 32

	// 会话ID (1字节长度 + 数据)
	sessionIDLen := int(data[offset])
	offset++
	if sessionIDLen > 0 {
		if offset+sessionIDLen > len(data) {
			return nil, errors.New("ClientHello session ID truncated")
		}
		msg.SessionID = data[offset : offset+sessionIDLen]
		offset += sessionIDLen
	}

	// 密码套件 (2字节长度 + 套件列表)
	if offset+2 > len(data) {
		return nil, errors.New("ClientHello cipher suites truncated")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+cipherSuitesLen > len(data) {
		return nil, errors.New("ClientHello cipher suites length exceeds data")
	}
	numSuites := cipherSuitesLen / 2
	msg.CipherSuites = make([]uint16, numSuites)
	for i := 0; i < numSuites; i++ {
		msg.CipherSuites[i] = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}

	// 压缩方法 (1字节长度 + 方法列表)
	if offset+1 > len(data) {
		return nil, errors.New("ClientHello compression methods truncated")
	}
	compressionMethodsLen := int(data[offset])
	offset++
	if offset+compressionMethodsLen > len(data) {
		return nil, errors.New("ClientHello compression methods length exceeds data")
	}
	msg.CompressionMethods = data[offset : offset+compressionMethodsLen]
	offset += compressionMethodsLen

	// 扩展 (2字节长度 + 扩展列表)
	if offset < len(data) {
		if offset+2 > len(data) {
			return nil, errors.New("ClientHello extensions length truncated")
		}
		extensionsLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		end := offset + extensionsLen
		if end > len(data) {
			return nil, errors.New("ClientHello extensions length exceeds data")
		}

		for offset < end {
			if offset+4 > end {
				return nil, errors.New("ClientHello extension header truncated")
			}
			extType := binary.BigEndian.Uint16(data[offset:])
			offset += 2
			extLen := int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
			if offset+extLen > end {
				return nil, errors.New("ClientHello extension data truncated")
			}

			extData := data[offset : offset+extLen]
			offset += extLen

			msg.Extensions = append(msg.Extensions, TLSExtension{
				Type: extType,
				Data: extData,
			})
		}
	}

	return msg, nil
}

// decodeServerHello 解析 ServerHello 消息
func decodeServerHello(data []byte) (*TLSServerHello, error) {
	msg := &TLSServerHello{}
	offset := 0

	// 版本 (2字节)
	if len(data) < 34 {
		return nil, errors.New("ServerHello too short")
	}
	msg.Version = TLSVersion(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// 随机数 (32字节)
	copy(msg.Random[:], data[offset:offset+32])
	offset += 32

	// 会话ID (1字节长度 + 数据)
	sessionIDLen := int(data[offset])
	offset++
	if sessionIDLen > 0 {
		if offset+sessionIDLen > len(data) {
			return nil, errors.New("ServerHello session ID truncated")
		}
		msg.SessionID = data[offset : offset+sessionIDLen]
		offset += sessionIDLen
	}

	// 密码套件 (2字节)
	if offset+2 > len(data) {
		return nil, errors.New("ServerHello cipher suite truncated")
	}
	msg.CipherSuite = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// 压缩方法 (1字节)
	if offset+1 > len(data) {
		return nil, errors.New("ServerHello compression method truncated")
	}
	msg.CompressionMethod = data[offset]
	offset++

	// 扩展 (2字节长度 + 扩展列表)
	if offset < len(data) {
		if offset+2 > len(data) {
			return nil, errors.New("ServerHello extensions length truncated")
		}
		extensionsLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		end := offset + extensionsLen
		if end > len(data) {
			return nil, errors.New("ServerHello extensions length exceeds data")
		}

		for offset < end {
			if offset+4 > end {
				return nil, errors.New("ServerHello extension header truncated")
			}
			extType := binary.BigEndian.Uint16(data[offset:])
			offset += 2
			extLen := int(binary.BigEndian.Uint16(data[offset:]))
			offset += 2
			if offset+extLen > end {
				return nil, errors.New("ServerHello extension data truncated")
			}

			extData := data[offset : offset+extLen]
			offset += extLen

			msg.Extensions = append(msg.Extensions, TLSExtension{
				Type: extType,
				Data: extData,
			})
		}
	}

	return msg, nil
}

// decodeCertificate 解析 Certificate 消息
func decodeCertificate(data []byte) (*TLSCertificate, error) {
	msg := &TLSCertificate{}
	offset := 0

	// 证书链长度 (3字节)
	if len(data) < 3 {
		return nil, errors.New("Certificate message too short")
	}
	certChainLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if offset+certChainLen != len(data) {
		return nil, fmt.Errorf("Certificate chain length mismatch: %d != %d",
			certChainLen, len(data)-offset)
	}

	// 解析每个证书
	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, errors.New("Certificate length truncated")
		}
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > len(data) {
			return nil, errors.New("Certificate data truncated")
		}

		cert := data[offset : offset+certLen]
		offset += certLen

		msg.Certificates = append(msg.Certificates, cert)
	}

	return msg, nil
}

// 辅助函数：获取握手消息类型字符串
func (t TLSHandshakeType) String() string {
	switch t {
	case HandshakeTypeHelloRequest:
		return "HelloRequest"
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeNewSessionTicket:
		return "NewSessionTicket"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeServerKeyExchange:
		return "ServerKeyExchange"
	case HandshakeTypeCertificateRequest:
		return "CertificateRequest"
	case HandshakeTypeServerHelloDone:
		return "ServerHelloDone"
	case HandshakeTypeCertificateVerify:
		return "CertificateVerify"
	case HandshakeTypeClientKeyExchange:
		return "ClientKeyExchange"
	case HandshakeTypeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
