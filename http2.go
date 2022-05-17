package tcpip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

const (
	StreamMagic   = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	FrameTypeData = iota - 1
	FrameTypeHeaders
	FrameTypePriority
	FrameTypeRstStream
	FrameTypeSettings
	FrameTypePushPromise
	FrameTypePing
	FrameTypeGoaway
	FrameTypeWindowUpdate
	FrameTypeContinuation
)

const (
	SettingsHeaderTableSize = iota + 1
	SettingsEnablePush
	SettingsMaxCouncurrentStreams
	SettingsInitialWindowSize
	SettingsHMaxFrameSize
	SettingsMaxHeaderListSize
)

type Http2Header struct {
	Name  string
	Value string
}

var StaticHttp2Table = []Http2Header{
	{Name: ":authority"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"},
	{Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"},
	{Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"},
	{Name: "accept-language"},
	{Name: "accept-ranges"},
	{Name: "accept"},
	{Name: "access-control-allow-origin"},
	{Name: "age"},
	{Name: "allow"},
	{Name: "authorization"},
	{Name: "cache-control"},
	{Name: "content-disposition"},
	{Name: "content-encoding"},
	{Name: "content-language"},
	{Name: "content-length"},
	{Name: "content-location"},
	{Name: "content-range"},
	{Name: "content-type"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "except"},
	{Name: "expires"},
	{Name: "from"},
	{Name: "host"},
	{Name: "if-match"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "if-range"},
	{Name: "if-unmodified-since"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "max-forwards"},
	{Name: "proxy-authenticate"},
	{Name: "proxy-authorization"},
	{Name: "range"},
	{Name: "referer"},
	{Name: "refresh"},
	{Name: "retry-after"},
	{Name: "server"},
	{Name: "set-cookie"},
	{Name: "strict-transport-security"},
	{Name: "transfer-encoding"},
	{Name: "user-agent"},
	{Name: "vary"},
	{Name: "via"},
	{Name: "www-authenticate"},
}

type Http2Frame struct {
	Length           []byte
	Type             []byte
	Flags            []byte
	StreamIdentifier []byte
	Value            []byte
}

type SettingsFrame struct {
	SettingsIdentifier []byte
	Value              []byte
}

type WindowsUpdateFrame struct {
	StreamIdentifier     []byte
	WindowsSizeIncrement []byte
}

type HeadersFrame struct {
	HeaderBlockFragement []byte
	Http2Headers         []Http2Header
}

type ParsedHttp2Frame struct {
	Type  int
	Frame interface{}
}

func createConnectionPreface() (prism []byte) {
	str := fmt.Sprintf("%x", StreamMagic)

	for i, _ := range str {
		if i%2 == 0 {
			b, _ := strconv.ParseInt(str[i:i+2], 16, 8)
			prism = append(prism, byte(b))
		}
	}

	return prism
}

func createSettings() Http2Frame {

	// EnablePushをセット
	headers := toByteArr(SettingsFrame{
		SettingsIdentifier: UintTo2byte(uint16(SettingsEnablePush)),
		Value:              []byte{0x00, 0x00, 0x00, 0x00},
	})
	// Initial Window Sizeをセット
	headers = append(headers, toByteArr(SettingsFrame{
		SettingsIdentifier: UintTo2byte(uint16(SettingsInitialWindowSize)),
		Value:              []byte{0x00, 0x40, 0x00, 0x00},
	})...)

	// Max Header List Size をセット
	headers = append(headers, toByteArr(SettingsFrame{
		SettingsIdentifier: UintTo2byte(uint16(SettingsMaxHeaderListSize)),
		Value:              []byte{0x00, 0xa0, 0x00, 0x00},
	})...)

	return Http2Frame{
		Length:           UintTo3byte(uint32(uint16(len(headers)))),
		Type:             []byte{FrameTypeSettings},
		Flags:            []byte{0x00},
		StreamIdentifier: []byte{0x00, 0x00, 0x00, 0x00},
		Value:            headers,
	}

}

func CreateFirstFrametoServer() []byte {
	var packet []byte

	preface := createConnectionPreface()
	frame := createSettings()
	update := Http2Frame{
		Length: UintTo3byte(4),
		Type:   []byte{FrameTypeWindowUpdate},
		Flags:  []byte{0x00},
		// 最初なのでストリーム番号は0
		StreamIdentifier: []byte{0x00, 0x00, 0x00, 0x00},
		// Windows Size Increment
		Value: []byte{0x40, 0x00, 0x00, 0x00},
	}

	// パケットデータにする
	packet = append(packet, preface...)
	packet = append(packet, toByteArr(frame)...)
	packet = append(packet, toByteArr(update)...)

	return packet
}

func CreateHeaderFrame() []byte {
	var headers []byte

	headers = append(headers, CreateHttp2Header(":authority", "127.0.0.1:18443")...)
	headers = append(headers, CreateHttp2Header("", "GET")...)
	headers = append(headers, CreateHttp2Header("", "/")...)
	headers = append(headers, CreateHttp2Header("", "https")...)
	headers = append(headers, CreateHttp2Header("accept-encoding", "gzip")...)
	headers = append(headers, CreateHttp2Header("user-agent", "Go-http-client/2.0")...)

	headerFrame := Http2Frame{
		Length: UintTo3byte(uint32(len(headers))),
		Type:   []byte{FrameTypeHeaders},
		// End HeadersとStreamがTrueなので5をセット
		Flags: []byte{0x05},
		// ストリーム番号は1になる
		StreamIdentifier: []byte{0x00, 0x00, 0x00, 0x01},
		// ヘッダを値としてセット
		Value: headers,
	}

	return toByteArr(headerFrame)
}

func getServerSettings(packet []byte) (frames []SettingsFrame) {

	for i := 0; i < len(packet); i++ {
		if i%6 == 0 {
			si := binary.BigEndian.Uint16(packet[i : i+2])
			switch si {
			case SettingsHeaderTableSize:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsHeaderTableSize},
					Value:              packet[i+2 : i+6],
				})
			case SettingsEnablePush:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsEnablePush},
					Value:              packet[i+2 : i+6],
				})
			case SettingsMaxCouncurrentStreams:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsMaxCouncurrentStreams},
					Value:              packet[i+2 : i+6],
				})
			case SettingsInitialWindowSize:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsInitialWindowSize},
					Value:              packet[i+2 : i+6],
				})
			case SettingsHMaxFrameSize:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsInitialWindowSize},
					Value:              packet[i+2 : i+6],
				})
			case SettingsMaxHeaderListSize:
				frames = append(frames, SettingsFrame{
					SettingsIdentifier: []byte{SettingsMaxHeaderListSize},
					Value:              packet[i+2 : i+6],
				})
			}
		}
	}
	fmt.Printf("FrameTypeSettings is %+v\n", frames)
	return frames
}

func parseHTTP2Frame(packet []byte) ParsedHttp2Frame {
	var frame ParsedHttp2Frame

	frameType := packet[3:4]
	//flags := packet[4:5]
	si := packet[5:9]

	switch int(frameType[0]) {
	case FrameTypeSettings:
		frame = ParsedHttp2Frame{
			Type:  FrameTypeSettings,
			Frame: getServerSettings(packet[9:]),
		}
	case FrameTypeWindowUpdate:
		updateFrame := WindowsUpdateFrame{
			StreamIdentifier:     si,
			WindowsSizeIncrement: packet[9:],
		}

		frame = ParsedHttp2Frame{
			Type:  FrameTypeWindowUpdate,
			Frame: updateFrame,
		}

		fmt.Printf("FrameTypeWindowUpdate : %+v\n", updateFrame)
	case FrameTypeHeaders:
		headers := DecodeHttp2Header(packet[9:])
		frame = ParsedHttp2Frame{
			Type:  FrameTypeHeaders,
			Frame: headers,
		}
		fmt.Printf("FrameTypeHeaders : %+v\n", headers)
	case FrameTypeData:
		frame = ParsedHttp2Frame{
			Type:  FrameTypeData,
			Frame: packet[9:],
		}
		fmt.Printf("FrameTypeData : %s\n", packet[9:])
	}

	return frame
}

func ParseHttp2Packet(packet []byte) (http2Frames []ParsedHttp2Frame) {
	// Lengthが0, Flagsが1, ACKS=trueだったらSkipする
	if bytes.Equal(packet[0:3], []byte{0x00, 0x00, 0x00}) {
		fmt.Println("Recv ACK for Settings")
		packet = packet[9:]
	}

	totalLen := len(packet)

	for i := 0; i < len(packet); i++ {
		length := sum3BytetoLength(packet[i : i+3])
		frame := parseHTTP2Frame(packet[i : i+int(length)+9])
		http2Frames = append(http2Frames, frame)
		// Frameが続いてるならiをインクリメントして次のFrameに進める
		if i+int(length)+9 < totalLen {
			i += (int(length) + 9) - 1
		} else {
			break
		}
	}

	return http2Frames
}
