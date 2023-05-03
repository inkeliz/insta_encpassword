// Package encpassword implements the password encryption used by Instagram,
// the encryption is a hybrid encryption, using public-key encryption to encrypt
// the symmetric key used for encrypting the password.
//
// The public-key encryption is done using NaCl's sealed box, which is based on
// XSalsa20, Poly1305 and Blake2b.
// The symmetric encryption is done using AES-256 in GCM mode. You should generate
// a random key and encrypt the message with that key and zero nonce.
//
// The result of both encryption's is then encoded using base64, which also contains
// information about the current version and id of the public key used.
package encpassword

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	// CurrentVersion is the current version of the password encryption.
	CurrentVersion = "10"
)

// PublicKey represents a public key used for encrypting passwords.
// You can get the public key from the Instagram web app.
type PublicKey struct {
	id      uint8
	version string
	key     [32]byte
}

// NewPublicKey creates a new public key from the given id, version and key.
func NewPublicKey(id, key string) (*PublicKey, error) {
	return NewPublicKeyCustom(id, CurrentVersion, key)
}

// NewPublicKeyCustom creates a new public key from the given id, version and key.
// Note, version is not checked, and may be invalid or not supported.
func NewPublicKeyCustom(id, version, key string) (*PublicKey, error) {
	k := [32]byte{}
	if _, err := hex.Decode(k[:], []byte(key)); err != nil {
		return nil, err
	}

	i, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	return &PublicKey{id: uint8(i), version: version, key: k}, nil
}

// EncryptPassword encrypts the given password using the given public key.
func EncryptPassword(pk *PublicKey, password string) (string, error) {
	return EncryptPasswordCustom(pk, password, time.Now().Unix(), rand.Reader)
}

// EncryptPasswordCustom encrypts the given password using the given public key,
// that allows to provide custom time and random source.
func EncryptPasswordCustom(pk *PublicKey, password string, time int64, random io.Reader) (string, error) {
	if pk == nil {
		return "", errors.New("public key is nil")
	}

	ephemeralKey := [32]byte{}
	if _, err := random.Read(ephemeralKey[:]); err != nil {
		return "", err
	}

	encryptedPass, err := encryptPassword(ephemeralKey[:], time, password)
	if err != nil {
		return "", err
	}

	encryptedKey, err := warpEphemeralKey(pk, ephemeralKey[:], random)
	if err != nil {
		return "", err
	}

	return format(pk, time, encryptedPass, encryptedKey)
}

// encryptPassword encrypts the given password using AES-GCM.
func encryptPassword(key []byte, unix int64, password string) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, _ := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	nonce := [12]byte{} // Uses zero nonce, because the key is random.
	return aesgcm.Seal(nil, nonce[:], []byte(password), []byte(strconv.FormatInt(unix, 10))), nil
}

// warpEphemeralKey encrypts the given key using the given public key, using NaCl's selead box.
func warpEphemeralKey(pk *PublicKey, key []byte, rand io.Reader) ([]byte, error) {
	return box.SealAnonymous(nil, key, &pk.key, rand)
}

// format formats the encrypted messages into a string.
func format(pk *PublicKey, unix int64, encPass []byte, encKey []byte) (string, error) {
	buf := bytes.Buffer{}
	buf.WriteByte(1)
	buf.WriteByte(pk.id)
	buf.WriteByte(uint8(len(encKey)))
	buf.WriteByte(uint8(len(encKey) >> 8))
	buf.Write(encKey[:])
	buf.Write(encPass[len(encPass)-16:]) // Tag
	buf.Write(encPass[:len(encPass)-16])

	return fmt.Sprintf("#PWD_INSTAGRAM_BROWSER:%s:%d:%s", pk.version, unix, base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}
