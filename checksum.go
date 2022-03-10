package main

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

func printByteArr(arr []byte) {
	for _, v := range arr {
		fmt.Printf("%x ", v)
	}
	fmt.Println()
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

func toByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	//rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		//field := rt.Field(i)
		//switch rv.Field(i).Interface().(type) {
		//case []uint8:
		//	fmt.Printf("%s\n", field.Name)
		//	b := rv.Field(i).Interface().([]uint8)
		//	fmt.Printf("%s 0x%x : %b\n", field.Name, b, b)
		//case [2]uint8:
		//	fmt.Printf("%s\n", field.Name)
		//	b := rv.Field(i).Interface().([2]uint8)
		//	fmt.Printf("%s 0x%x : %b\n", field.Name, b, b)
		//}
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

func calcChecksum(sum uint) []byte {

	dataByteSum := fmt.Sprintf("%b", sum)

	overFlowBitLength := len(dataByteSum) - 16

	overflow := dataByteSum[0:overFlowBitLength]
	bitData := dataByteSum[overFlowBitLength:]

	uintOverflow, _ := strconv.ParseUint(overflow, 2, overFlowBitLength)
	uintData, _ := strconv.ParseUint(bitData, 2, 16)

	//fmt.Printf("%b\n", uintOverflow)
	//fmt.Printf("%b\n", uintData)
	//fmt.Printf("%b\n", uintData+uintOverflow)

	var j = uint16(uintData + uintOverflow)

	return uintTo2byte(^j)
}
