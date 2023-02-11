# termotp - A terminal OTP codes generator.

## Description

**termotp** reads an encrypted vault export from your TOTP Android App (currently, only Aegis Authenticator is supported) and displays issuers, providers and a TOTP for each of them. The program uses no database and reads directly from the App export. Since backups are encrypted, your credentials never stay on the disk unencrypted. It's basically a pure terminal based way to generate TOTP tokens while keeping your credentials encrypted.

Future versions will read encrypted exports from other apps, such AndOTP and others.

**termotp** can display a simple table with issuers, accounts, and otps, or engage in an interactive fuzzy finder with the user.

A regular expression allows the selection of a group of entries. If called without a regexp, **termotp** will show all entries.

## Installation

There are a few ways to install **termotp**:

### Download from releases

To download and install the latest release, cut and paste the following shell command:

```bash
wget -q -O/tmp/install \
  'https://raw.githubusercontent.com/marcopaganini/installer/master/install.sh' && \
  sudo sh /tmp/install marcopaganini/termotp
```

### Compile and install yourself

If you have the Go compiler installed, just clone the repository and type `make`, followed by `make install`:

```bash
git clone https://github.com/marcopaganini/termotp
cd termotp
make
sudo make install
```

## Usage

The basic usage is:

```
termotp --input=file_glob [options] [entry_regexp}
```

### Options ###

**--input=file_glob**

Specifies the file or a glob matching more than one file holding the encrypted vault exports. If the glob expands to more than one file, **termotp** will pick the newest one. This is useful if you sync your phone vault exports to a directory on your computer (using syncthing, for example.). Aegis by default uses a date on the filename, so in case of multiple files being present, the latest one is what you usually want.

E.g.: Specifying `--input="/backups/aegis/*.json"` (note the quotes) will cause **termotop** to use the latest file named `*.json` in the `/backup/aegis` directory.

**--fuzzy**

Without any special options, **termotp** shows a formatted table of your TOTP providers and the calculated tokens. This option shows a simple TUI with a fuzzy selector. Hitting enter on an entry will print the otp to the standard output.

**---version**

Just print the current program version (or git commit number) and exit.

## Future plans

Add support for other OTP programs, like AndOTP, 2FA, etc. I'll proceed to do that once I have literature on the encrypted export formats for those programs.  For now, only Aegis Authenticator is supported.

## Related and similar programs

* Aegis authenticator for Android: http://getaegis.app
* Syncthing (available for multiple OSes): http://syncthing.net
* Similar program: [OTPCLient](https://github.com/paolostivanin/OTPClient) allows you to import different vault formats into its own encrypted vault. Has a graphical UI and a less capable CLI client.

## Author

Marco Paganini <paganini AT paganini dot net>
