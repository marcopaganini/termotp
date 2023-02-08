**NAME**

termotp - A terminal OTP codes generator.

**SYNOPSYS**

termotp --input=file_glob [options] [entry_regexp}

**DESCRIPTION**

**termotp** reads an encrypted vault export from your TOTP Android App
(currently, only Aegis Authenticator is supported) and displays issuers,
providers and a TOTP for each of them. The program uses no database and reads
directly from the App export. Since backups are encrypted, your credentials
never stay on the disk unencrypted.

Future versions will read encrypted exports from other apps, such AndOTP and others.

**termotp** can display a simple table with issuers, accounts, and otps, or
engage in an interactive fuzzy finder with the user.

A regular expression allows the selection of a group of entries. If called
without a regexp, **termotp** will show all entries.

**OPTIONS**

**--input=file_glob**

Specifies the file or a glob matching more than one file holding the encrypted
vault exports. If the glob expands to more than one file, **termotp** will pick
the newest one. This is useful if you sync your phone vault exports to a
directory on your computer (using syncthing, for example.). Aegis by default
uses a date on the filename, so in case of multiple files being present, the
latest one is what you usually want.

E.g.: Specifying `--input="/backups/aegis/*.json"` (note the quotes) will cause
**termotop** to use the latest file named `*.json` in the `/backup/aegis`
directory.

**--fuzzy**

Without any special options, **termotp** shows a formatted table of your
TOTP providers and the calculated tokens. This option shows a simple TUI
with a fuzzy selector. Hitting enter on an entry will print the otp
to the standard output.

**---version**

Just print the current program version (or git commit number) and exit.

**FUTURE PLANS**

Add support for other OTP programs, like AndOTP, 2FA, etc. I'll proceed to do
that once I have literature on the encrypted export formats for those programs.
For now, only Aegis Authenticator is supported.

**LINKS**

* Aegis authenticator: http://getaegis.app
* Syncthing: http://syncthing.net

**AUTHOR**

Marco Paganini <paganini AT paganini dot net>
