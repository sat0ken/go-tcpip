package main

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

func paddingZero(arr []byte) []byte {
	padarr := append(arr, 0x00)
	return padarr
}

func printByteArr(arr []byte) string {
	var str string
	for _, v := range arr {
		//fmt.Printf("%#x ", v)
		str += fmt.Sprintf("%x ", v)
	}
	return str
}

func sum3BytetoLength(arr []byte) uint64 {
	length, _ := strconv.ParseUint(fmt.Sprintf("%x", arr), 16, 16)
	return length
}

func sumByteArr(arr []byte) uint {
	var sum uint
	for i := 0; i < len(arr); i++ {
		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(arr[i:]))
		}
	}
	//fmt.Printf("0x%x : %b\n", sum, sum)
	return sum
}

func checktoByteArr(value interface{}) {
	rv := reflect.ValueOf(value)
	rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		field := rt.Field(i)

		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
		fmt.Printf("%s : %x\n", field.Name, b)
	}
}

// 各構造体のフィールドが持つbyteをflatな配列にする
func toByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	//rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		//field := rt.Field(i)
		// fmt.Printf("%s\n", field.Name)
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return arr
}

func toByteLen(value interface{}) uint16 {
	rv := reflect.ValueOf(value)
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return uint16(len(arr))
}

func uintTo2byte(data uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return b
}

func uintTo3byte(data uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return b[1:]
}

func checksum(sum uint) []byte {
	// https://el.jibun.atmarkit.co.jp/hiro/2013/07/tcp-f933.html
	// 22DA6 - 20000 + 2 = 2DA8となり、2DA8をビット反転
	val := sum - (sum>>16)<<16 + (sum >> 16) ^ 0xffff
	return uintTo2byte(uint16(val))
}
