package main

import (
	"fmt"
	"reflect"
)

type HttpRequest struct {
	Request []byte
	Header  HttpHeader
	Body    []byte
}

type HttpHeader struct {
	Host       []byte
	UserAgent  []byte
	Accept     []byte
	Connection []byte
}

func (*HttpRequest) NewGetRequest(url, host string) HttpRequest {
	header := HttpHeader{
		Host:       []byte(fmt.Sprintf("Host: %s", host)),
		UserAgent:  []byte(`User-Agent: curl/7.68.0`),
		Accept:     []byte(`Accept: */*`),
		Connection: []byte(`Connection: close`),
	}
	return HttpRequest{
		Request: []byte(fmt.Sprintf("GET %s HTTP/1.1", url)),
		Header:  header,
	}
}

// https://www.infraexpert.com/study/tcpip16.html
func (*HttpRequest) reqtoByteArr(request HttpRequest) []byte {
	var packet []byte
	var CRLF = []byte{0x0d, 0x0a}

	packet = append(packet, request.Request...)
	packet = append(packet, CRLF...)

	rv := reflect.ValueOf(request.Header)
	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		packet = append(packet, b...)
		packet = append(packet, CRLF...)
	}
	// 空白行を入れて戻す
	packet = append(packet, CRLF...)
	return packet
}
