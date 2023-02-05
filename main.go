// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/xlzd/gotp"
)

const (
	keylen = 32
)

// BuildVersion holds the current git head version number.
// this is filled in by the build process (make).
var BuildVersion string

func main() {
	var (
		input = flag.String("input", "", "Input (encrypted) json file.")
	)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()

	if *input == "" {
		log.Fatal("Please specify input file with --input")
	}

	db, err := aegisDecrypt(*input)
	if err != nil {
		log.Fatal(err)
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
