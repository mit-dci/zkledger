package zkledger

import (
	"fmt"
	"testing"
)

func TestLocalLedger(t *testing.T) {
	l := MakeLocalLedger()
	etx := EncryptedTransaction{}
	idx := l.add(&etx)
	if idx != 0 {
		t.Errorf("Transaction added incorrectly %v\n", idx)
	}
	for i := 1; i < 10; i++ {
		idx := l.add(&etx)
		if idx != i {
			t.Errorf("Transaction added incorrectly %v\n", idx)
		}
	}
	fmt.Printf("Passed TestLocalLedger\n")
}

func TestLedger(t *testing.T) {
	l := MakeLedger(2)
	etx := EncryptedTransaction{}
	idx := l.add(&etx)
	if idx != 0 {
		t.Errorf("Transaction added incorrectly %v\n", idx)
	}
	for i := 1; i < 10; i++ {
		idx := l.add(&etx)
		if idx != i {
			t.Errorf("Transaction added incorrectly %v\n", idx)
		}
	}
	fmt.Printf("Passed TestLedger\n")
}
