// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// aegisEncryptedJSON represents an encrypted Aegis JSON export file.
type aegisEncryptedJSON struct {
	Version int `json:"version"`
	Header  struct {
		Slots []struct {
			Type      int    `json:"type"`
			UUID      string `json:"uuid"`
			Key       string `json:"key"`
			KeyParams struct {
				Nonce string `json:"nonce"`
				Tag   string `json:"tag"`
			} `json:"key_params"`
			N    int    `json:"n"`
			R    int    `json:"r"`
			P    int    `json:"p"`
			Salt string `json:"salt"`
		} `json:"slots"`
		Params struct {
			Nonce string `json:"nonce"`
			Tag   string `json:"tag"`
		} `json:"params"`
	} `json:"header"`
	Db string `json:"db"`
}

// aegisJSON represents a plain Aegis JSON export file.
type aegisJSON struct {
	Version int `json:"version"`
	Entries []struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Issuer string `json:"issuer"`
		Icon   string `json:"icon"`
		Info   struct {
			Secret string `json:"secret"`
			Digits int    `json:"digits"`
			Algo   string `json:"algo"`
			Period int    `json:"period"`
		} `json:"info"`
	}
}

// newAES creates a new AESGCM cipher.
func newAES(key []byte) (cipher.AEAD, error) {
	// AES GCM decrypt.
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}

// readPassword reads the user password from the terminal.
func readPassword() ([]byte, error) {
	savedState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	defer term.Restore(int(os.Stdin.Fd()), savedState)

	terminal := term.NewTerminal(os.Stdin, ">")
	password, err := terminal.ReadPassword("Enter password: ")
	if err != nil {
		return nil, err
	}
	return []byte(password), nil
}

// aegisDecrypt opens an encrypted Aegis JSON export file and
// returns the plain json contents.
func aegisDecrypt(fname string) ([]byte, error) {
	buf, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	encJSON := aegisEncryptedJSON{}
	if err := json.Unmarshal(buf, &encJSON); err != nil {
		return nil, err
	}

	var masterkey []byte
	password, err := readPassword()
	if err != nil {
		return nil, err
	}

	// Extract all master key slots from header.
	// Exit when a valid masterkey has been found.
	for _, slot := range encJSON.Header.Slots {
		var (
			nonce   []byte
			keyslot []byte
			tag     []byte
			salt    []byte
		)

		if slot.Type != 1 {
			continue
		}
		if salt, err = hex.DecodeString(slot.Salt); err != nil {
			return nil, fmt.Errorf("Slot salt: %v", err)
		}

		key, err := scrypt.Key(password, salt, slot.N, slot.R, slot.P, keylen)
		if err != nil {
			return nil, err
		}

		// AES GCM decrypt.
		aesgcm, err := newAES(key)
		if err != nil {
			return nil, err
		}

		if nonce, err = hex.DecodeString(slot.KeyParams.Nonce); err != nil {
			return nil, fmt.Errorf("Slot nonce: %v", err)
		}
		if tag, err = hex.DecodeString(slot.KeyParams.Tag); err != nil {
			return nil, fmt.Errorf("Slot tag: %v", err)
		}
		if keyslot, err = hex.DecodeString(slot.Key); err != nil {
			return nil, fmt.Errorf("Slot key: %v", err)
		}

		// ciphertext := keyslot + tag
		ciphertext := keyslot
		ciphertext = append(ciphertext, tag...)

		// Decrypt and break out of the loop if found. If not, try the next slot.
		masterkey, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			// Issue a warning only, but continue.
			log.Print(err)
			continue
		}
		break
	}

	if len(masterkey) == 0 {
		return nil, errors.New("Unable to decrypt the master key with the given password")
	}

	// Decode DB contents.
	content, err := base64.StdEncoding.DecodeString(encJSON.Db)
	if err != nil {
		return nil, err
	}

	// Decrypt the vault contents using the master key.
	cipher, err := newAES(masterkey)
	if err != nil {
		return nil, err
	}

	nonce, err := hex.DecodeString(encJSON.Header.Params.Nonce)
	if err != nil {
		return nil, fmt.Errorf("Params nonce: %v", err)
	}
	tag, err := hex.DecodeString(encJSON.Header.Params.Tag)
	if err != nil {
		return nil, fmt.Errorf("Params tag: %v", err)
	}

	data := append(content, tag...)

	// Decrypt and return.
	db, err := cipher.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return db, nil
}
