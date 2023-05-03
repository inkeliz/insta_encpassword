package encpassword

import (
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

func TestEncryptPassword(t *testing.T) {
	pk, err := NewPublicKeyCustom("128", "10", "7304c07abe5abd80102474de4897f6cff08217a2c0d224ffb1adfd7e65b16d0d")
	if err != nil {
		t.Error(err)
	}

	rand, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	date := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	res, err := EncryptPasswordCustom(pk, "123", date, rand)
	if err != nil {
		t.Error(err)
	}

	expected := "#PWD_INSTAGRAM_BROWSER:10:1672531200:AYBQAOaRs6TKYi421c7gEmdLu/CIUZaX1NXQDpxKfOr40j8P4dtDmyQ/UxKUCrgfn+74ruaDjWOehHObA+ZbuQ3ERLVyn0dOKv4wnPHV+yvNL4gvfbJUk5Z8JlNfStxxEMlc53/ntQ=="
	if res != expected {
		t.Errorf("Expected %s, got %s", expected, res)
	}
}
