package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	keylen = 32
)

// BuildVersion holds the current git head version number.
// this is filled in by the build process (make).
var BuildVersion string

// JSON structures for encrypted Aegis JSON files.
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

// JSON structure for the plain Aegis files.
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

func stringToHexOrDie(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return ret
}

func newAESOrDie(key []byte) cipher.AEAD {
	// AES GCM decrypt.
	b, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		log.Fatal(err)
	}
	return aesgcm
}

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

func main() {
	var (
		input = flag.String("input", "", "Input (encrypted) json file.")
	)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()

	if *input == "" {
		log.Fatal("Please specify input file with --input")
	}

	buf, err := os.ReadFile(*input)
	if err != nil {
		log.Fatal(err)
	}
	encJSON := aegisEncryptedJSON{}
	if err := json.Unmarshal(buf, &encJSON); err != nil {
		log.Fatal(err)
	}

	var masterkey []byte
	password, err := readPassword()
	if err != nil {
		log.Fatal(err)
	}

	// Extract all masterkey slots from header.
	// Exit when a valid masterkey has been found.
	for _, slot := range encJSON.Header.Slots {
		if slot.Type != 1 {
			continue
		}
		salt := stringToHexOrDie(slot.Salt)

		key, err := scrypt.Key(password, salt, slot.N, slot.R, slot.P, keylen)
		if err != nil {
			log.Fatal(err)
		}

		// AES GCM decrypt.
		aesgcm := newAESOrDie(key)

		nonce := stringToHexOrDie(slot.KeyParams.Nonce)
		keyslot := stringToHexOrDie(slot.Key)
		tag := stringToHexOrDie(slot.KeyParams.Tag)

		// ciphertext := keyslot + tag
		ciphertext := keyslot
		ciphertext = append(ciphertext, tag...)

		masterkey, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Print(err)
			continue
		}
		break
	}

	if len(masterkey) == 0 {
		log.Fatal("Unable to decrypt the master key with the given password")
	}

	content, err := base64.StdEncoding.DecodeString(encJSON.Db)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the vault contents using the master key.
	cipher := newAESOrDie(masterkey)
	nonce := stringToHexOrDie(encJSON.Header.Params.Nonce)
	tag := stringToHexOrDie(encJSON.Header.Params.Tag)

	data := append(content, tag...)

	db, err := cipher.Open(nil, nonce, data, nil)
	if err != nil {
		log.Print(err)
	}

	// Print entries.
	tbl := table.NewWriter()
	automerge := table.RowConfig{AutoMerge: true}

	tbl.AppendHeader(table.Row{"Issuer", "Name", "OTP"}, automerge)

	plainJSON := aegisJSON{}
	if err := json.Unmarshal(db, &plainJSON); err != nil {
		log.Fatal(err)
	}
	for _, entry := range plainJSON.Entries {
		token := "Unknown OTP type: " + entry.Type
		if entry.Type == "totp" {
			token = gotp.NewDefaultTOTP(entry.Info.Secret).Now()
		}
		tbl.AppendRow(table.Row{entry.Issuer, entry.Name, token}, automerge)
	}

	// Emit table.
	tbl.SortBy([]table.SortBy{
		{Name: "Issuer", Mode: table.Asc},
		{Name: "Name", Mode: table.Asc},
	})
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})
	tbl.SetStyle(table.StyleLight)
	tbl.Style().Options.SeparateRows = true
	tbl.Render()
}
