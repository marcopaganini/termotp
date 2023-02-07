// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/romana/rlog"
)

// BuildVersion holds the current git head version number.
// this is filled in by the build process (make).
var BuildVersion string

// otpEntry holds the representation of the internal vault.
type otpEntry struct {
	issuer  string
	account string
	token   string
}

// die logs a message with rlog.Critical and exists with a return code.
func die(v ...any) {
	rlog.Critical(v...)
	os.Exit(1)
}

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

	if *flagInput == "" {
		die("Please specify input file with --input")
	}

	if len(flag.Args()) > 1 {
		fmt.Println("Specify one or zero regular expressions to match.")
		flag.PrintDefaults()
		return
	}

	// Get input file from the input files glob.
	input, err := inputFile(*flagInput)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Input file: %s", input)

	// By default, match everything (.) unless overriden by an argument.
	r := "."
	if len(flag.Args()) > 0 {
		r = "(?i)" + flag.Args()[0]
	}
	rematch, err := regexp.Compile(r)
	if err != nil {
		die(err)
	}

	db, err := aegisDecrypt(input)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Decoded JSON:\n%s\n", string(db))

	vault, err := filterAegisVault(db, rematch)
	if err != nil {
		die(err)
	}

	if len(vault) == 0 {
		rlog.Info("No matching entries found.")
		return
	}

	// Print entries.
	tbl := table.NewWriter()
	automerge := table.RowConfig{AutoMerge: true}

	tbl.AppendHeader(table.Row{"Issuer", "Name", "OTP"}, automerge)

	for _, v := range vault {
		tbl.AppendRow(table.Row{v.issuer, v.account, v.token}, automerge)
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
