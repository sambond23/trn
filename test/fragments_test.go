package test

import (
	"testing"
	"trn/internal"
)

func TestFragment(t *testing.T) {
	data := []byte("test data")
	parts, err := internal.SplitData(data, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := internal.CombineData(parts)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(data) {
		t.Errorf("restored data mismatch")
	}
}
