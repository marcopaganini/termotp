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
	"os"
	"regexp"
	"strings"

	"github.com/romana/rlog"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	aegisKeyLen = 32
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

// readPassword reads the user password from the terminal.  If the input is a
// terminal, it uses terminal specific codes to turn off typing echo. If the
// input is not a terminal, it assumes we can read the password directly from
// it (E.g, when redirecting from a process or a file.)
func readPassword() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}

	// Test if we're reading from pipe or terminal.

	var password string
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		// Reading from terminal.
		savedState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		defer term.Restore(int(os.Stdin.Fd()), savedState)

		terminal := term.NewTerminal(os.Stdin, ">")
		password, err = terminal.ReadPassword("Enter password: ")
		if err != nil {
			return nil, err
		}
	} else {
		// 256-byte passwords ought to be enough for everybody :)
		buf := make([]byte, 256)
		if _, err := os.Stdin.Read(buf); err != nil {
			return nil, err
		}
		password = strings.TrimRight(string(buf), "\r\n\x00")
	}
	return []byte(password), nil
}

// filterAegisVault filters an Aegis plain JSON into our internal
// representation of the vault, using "rematch" as a regular expression to
// match the issuer or account.
func filterAegisVault(plainJSON []byte, rematch *regexp.Regexp) ([]otpEntry, error) {
	vault := &aegisJSON{}
	if err := json.Unmarshal(plainJSON, &vault); err != nil {
		return nil, err
	}

	ret := []otpEntry{}

	for _, entry := range vault.Entries {
		token := "Unknown OTP type: " + entry.Type
		if entry.Type == "totp" {
			token = gotp.NewDefaultTOTP(entry.Info.Secret).Now()
		}
		if rematch.MatchString(entry.Issuer) || rematch.MatchString(entry.Name) {
			ret = append(ret, otpEntry{
				Issuer:  entry.Issuer,
				Account: entry.Name,
				Token:   token,
			})
		}
	}
	return ret, nil
}

// aegisDecrypt opens an encrypted Aegis JSON export file and
// returns the plain json contents.
func aegisDecrypt(fname string, password []byte) ([]byte, error) {
	buf, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	encJSON := aegisEncryptedJSON{}
	if err := json.Unmarshal(buf, &encJSON); err != nil {
		return nil, err
	}

	// Extract all master key slots from header.
	// Exit when a valid masterkey has been found.
	var masterkey []byte
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
			return nil, fmt.Errorf("slot salt: %v", err)
		}

		key, err := scrypt.Key(password, salt, slot.N, slot.R, slot.P, aegisKeyLen)
		if err != nil {
			return nil, err
		}

		// AES GCM decrypt.
		aesgcm, err := newAES(key)
		if err != nil {
			return nil, err
		}

		if nonce, err = hex.DecodeString(slot.KeyParams.Nonce); err != nil {
			return nil, fmt.Errorf("slot nonce: %v", err)
		}
		if tag, err = hex.DecodeString(slot.KeyParams.Tag); err != nil {
			return nil, fmt.Errorf("slot tag: %v", err)
		}
		if keyslot, err = hex.DecodeString(slot.Key); err != nil {
			return nil, fmt.Errorf("slot key: %v", err)
		}

		// ciphertext := keyslot + tag
		ciphertext := keyslot
		ciphertext = append(ciphertext, tag...)

		// Decrypt and break out of the loop if found. If not, try the next slot.
		masterkey, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			// Issue a warning only, but continue.
			rlog.Debug(err)
			continue
		}
		break
	}

	if len(masterkey) == 0 {
		return nil, errors.New("unable to decrypt the master key with the given password")
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
		return nil, fmt.Errorf("params nonce: %v", err)
	}
	tag, err := hex.DecodeString(encJSON.Header.Params.Tag)
	if err != nil {
		return nil, fmt.Errorf("params tag: %v", err)
	}

	data := append(content, tag...)

	// Decrypt and return.
	db, err := cipher.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return db, nil
}
