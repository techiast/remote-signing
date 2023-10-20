package address

import (
	"bytes"
	"encoding/hex"
	"reflect"
)

type IAddress interface {
	String() string
	Bytes() []byte
	ID() []byte
	IsContract() bool
	Equal(IAddress) bool
}

const (
	AddressIDBytes = 20
	AddressBytes   = AddressIDBytes + 1
)

type Address [AddressBytes]byte

func (a *Address) IsContract() bool {
	return false
}

func (a *Address) String() string {
	return "hx" + hex.EncodeToString(a[1:])
}

func (a *Address) Bytes() []byte {
	return (*a)[:]
}

// BytesPart returns part of address without type prefix.
func (a *Address) ID() []byte {
	return (*a)[1:]
}

func (a *Address) Equal(a2 IAddress) bool {
	a2IsNil := a2 == nil || reflect.ValueOf(a2).IsNil()
	if a2IsNil && a == nil {
		return true
	}
	if a2IsNil || a == nil {
		return false
	}
	return a.IsContract() == a2.IsContract() && bytes.Equal(a.ID(), a2.ID())
}

func NewAddress(newAddress []byte) *Address {
	a := new(Address)
	a.SetTypeAndID(false, newAddress)

	return a
}

var zeroBuffer [AddressIDBytes]byte

func (a *Address) SetTypeAndID(ic bool, id []byte) {
	switch {
	case len(id) < AddressIDBytes:
		bp := 1 + AddressIDBytes - len(id)
		copy(a[1:bp], zeroBuffer[:])
		copy(a[bp:], id)
	default:
		copy(a[1:], id)
	}
	if ic {
		a[0] = 1
	} else {
		a[0] = 0
	}
}
