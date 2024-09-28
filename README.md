[![Go Report Card](https://goreportcard.com/badge/github.com/marcopaganini/termotp)](https://goreportcard.com/report/github.com/marcopaganini/termotp)

# termotp - A terminal OTP codes generator.

## Description

**termotp** reads an encrypted vault export from your TOTP Android App (currently, only Aegis Authenticator is supported) and displays issuers, providers and a TOTP for each of them. The program uses no database and reads directly from the App export. Since backups are encrypted, your credentials never stay on the disk unencrypted. It's basically a pure terminal based way to generate TOTP tokens while keeping your credentials encrypted.

Future versions will read encrypted exports from other apps, such AndOTP and others.

**termotp** can display a simple table with issuers, accounts, and otps, or engage in an interactive fuzzy finder with the user.

A regular expression allows the selection of a group of entries. If called without a regexp, **termotp** will show all entries.

## Why another CLI/TUI based authenticator?

Similar CLI/TUI applications exist, but most (if not all) of them focus on being a full HOTP/TOTP code generator. These applications keep a local database with the secrets and synchronization of tokens between the CLI application and your mobile app needs to be done manually (and in some cases, by adding the secrets directly). While some CLI applications offer *import* capabilities, not many can *export* into other formats. Even with import/export, both databases need to me synchronized carefully, or loss of data may occur.

**termotp**'s main purpose is to use the export file from mobile apps *directly*. There are no other databases, no possibility of adding new codes via **termotp**, so no chance for data loss of synchronization issues. It also has both a CLI and a simple TUI mode, which not all alternatives offer.

## Installation

There are a few ways to install **termotp**:

### Direct download from releases

To download and install the latest release into `/usr/local/bin` (requires
root), cut and paste the following shell command:

```bash
curl -s \
  'https://raw.githubusercontent.com/marcopaganini/termotp/master/install.sh' |
  sudo sh -s -- marcopaganini/termotp
```

To download and install the latest release into another directory (say, `~/.local/bin`):

```bash
curl -s \
  'https://raw.githubusercontent.com/marcopaganini/termotp/master/install.sh' |
  sh -s -- marcopaganini/termotp "${HOME}/.local/bin"
```

### Compile and install yourself

If you have the Go compiler installed, just clone the repository and type `make`, followed by `make install`:

```bash
git clone https://github.com/marcopaganini/termotp
cd termotp
make
sudo make install
```

### Linux packages

You'll also find packages for multiple distributions (DEB/RPM/APK files, etc) in the
[Releases](https://github.com/marcopaganini/termotp/releases/) are of the repository.

## Usage

The basic usage is:

```
termotp --input=file_glob [options] [entry_regexp}
```

### Options ###

**--input=file_glob**

Specifies the file or a glob matching more than one file holding the encrypted vault exports. If the glob expands to more than one file, **termotp** will pick the newest one. This is useful if you sync your phone vault exports to a directory on your computer (using syncthing, for example.). Aegis by default uses a date on the filename, so in case of multiple files being present, the latest one is what you usually want.

E.g.: Specifying `--input="/backups/aegis/*.json"` (note the quotes) will cause **termotop** to use the latest file named `*.json` in the `/backup/aegis` directory.

**--fzf**

Uses [fzf](https://github.com/junegunn/fzf) to select the desired OTP. The `fzf` binary must be installed on the system.

**--fuzzy**

Without any special options, **termotp** shows a formatted table of your TOTP providers and the calculated tokens. This option shows a simple TUI with a fuzzy selector. Hitting enter on an entry will print the otp to the standard output.

**--json**

Emits the output in JSON format.

**--plain**

Produces a plain listing of the vault.

**--set-keyring**

Read the password from the keyboard and write it to the keyring. This option causes all other options to be silently ignored.

Under OS X, you'll need the `/usr/bin/security` binary to interface with the OS X keychain. This binary should be available by default.

In Linux and BSD implementations, this depends on the [Secret Service](https://specifications.freedesktop.org/secret-service/latest/) dbus interface provided by [Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring). These implementations are installed and started by default on most modern distributions.

Please note that this assumes that the `login` collection exists in the keyring (the default on most distros).  If it doesn't, use [Seahorse](https://wiki.gnome.org/Apps/Seahorse) to create it:

* Open `seahorse`
* Go to `File` > `New` > `Password Keyring`
* Click `Continue`
* When asked for a name, use `login`.

**--use-keyring**

Read the password from the `login` keyring (which should be open by default after login) instead of the keyboard. This allows passwordless operation while maintaining your vault encrypted.

Make sure to write your password to the keyring with `--set-keyring` before using this option.

**---version**

Just print the current program version (or git commit number) and exit.

## Future plans

Add support for other OTP programs, like AndOTP, 2FA, etc. I'll proceed to do that once I have literature on the encrypted export formats for those programs.  For now, only Aegis Authenticator is supported.

## Related and similar programs

* [Aegis authenticator for Android](http://getaegis.app): It's my TOTP app of choice on Android (Lots of features and open source!)
* [cotp](https://github.com/replydev/cotp): Capable TUI based OTP generator. Can import external files, but uses its own database on disk.
* [OTPCLient](https://github.com/paolostivanin/OTPClient) allows you to import different vault formats into its own encrypted vault. Has a graphical UI and a less capable CLI client.
* [oathtool](https://www.nongnu.org/oath-toolkit/): Bare bones CLI authenticator.
* [2fa](https://github.com/rsc/2fa): Another bare bones OTP generator that uses its own database (manual import).
* [Syncthing](http://syncthing.net): Allows you to sync files directly between multiple devices (including your phone.)

## Thanks

* https://github.com/zalando/ for their Keyring manipulation library.
* https://github.com/sam-artuso and http://github.com/timkgh for their great feature requests.

## Author

Marco Paganini <paganini AT paganini dot net>
