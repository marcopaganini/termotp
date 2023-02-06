// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/romana/rlog"
	"github.com/xlzd/gotp"
)

const (
	keylen = 32
)

// BuildVersion holds the current git head version number.
// this is filled in by the build process (make).
var BuildVersion string

// die logs a message with rlog.Critical and exists with a return code.
func die(v ...any) {
	rlog.Critical(v...)
	os.Exit(1)
}

// dief logs a message with rlog.Critical and exists with a return code.
//func dief(format string, v ...any) {
//    rlog.Criticalf(format, v)
//    os.Exit(1)
//}

// inputFile expands the glob passed as an argument and returns the file with
// the most recent modification time in the list.
func inputFile(fileglob string) (string, error) {
	files, err := filepath.Glob(fileglob)
	if err != nil {
		return "", err
	}
	if files == nil {
		return "", fmt.Errorf("No input files match %q", fileglob)
	}
	// Find the file with the newest mtime and return.
	var (
		ntime time.Time
		nfile string
	)
	for _, file := range files {
		fi, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		if fi.ModTime().After(ntime) {
			ntime = fi.ModTime()
			nfile = file
		}
	}
	return nfile, nil
}

func main() {
	var (
		flagInput = flag.String("input", "", "Input (encrypted) json file glob.")
	)

	flag.Parse()

	input, err := inputFile(*flagInput)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Input file: %s", input)

	if *flagInput == "" {
		die("Please specify input file with --input")
	}

	db, err := aegisDecrypt(input)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Decoded JSON:\n%s\n", string(db))

	// Print entries.
	tbl := table.NewWriter()
	automerge := table.RowConfig{AutoMerge: true}

	tbl.AppendHeader(table.Row{"Issuer", "Name", "OTP"}, automerge)

	plainJSON := aegisJSON{}
	if err := json.Unmarshal(db, &plainJSON); err != nil {
		die(err)
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
