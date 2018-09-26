# Troubleshooting

## Basics

 - Have you searched [known issues]?
 - Have you tried rebooting? (Kidding!)
 - Did you read all the items on this page?
 - Then you should contact [support]!

## Bug Reproduction
Running Binary Ninja with debug logging will make your bug report more useful.

```
./binaryninja --debug --stderr-log
```

Alternatively, it might be easier to save debug logs to a file instead:

```
./binaryninja -d -l logfile.txt
```

(note that both long and short-form of the command-line arguments are demonstrated in the above examples)

## Plugin Troubleshooting

While third party plugins are not officially supported, there are a number of troubleshooting tips that can help identify the cause. The most important is to enable debug logging as suggested in the previous section. This will often highlight problems with python paths or any other issues that prevent plugins from running.

Additionally, if you're having trouble running a plugin in headless mode (without a GUI calling directly into the core), make sure you'er running the Commercial version of Binary Ninja as the Student/Non-Commercial edition does not support headless processing.

Next, if running a python plugin, make sure the python requirements are met by your existing installation. Note that on windows, the bundled python is used and python requirements should be installed either by manually copying the modules to the `plugins` [folder](/getting-started/#directories).


## License Problems

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely un-install and [recover][recover] the latest installer and license. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](/getting-started/#license).
- If you need to change the email address on your license, contact [support].

## OS X

While OS X is generally the most trouble-free environment for Binary Ninja, very old versions may have problems with the RPATH for our binaries and libraries. There are two solutions. First, run Binary Ninja with: 

```
DYLD_LIBRARY_PATH="/Applications/Binary Ninja.app/Contents/MacOS" /Applications/Binary\ Ninja.app/Contents/MacOS/binaryninja
```

Or second, modify the binary itself using the [install_name_tool](https://blogs.oracle.com/dipol/dynamic-libraries,-rpath,-and-mac-os).

## Linux

Given the diversity of Linux distributions, some work-arounds are required to run Binary Ninja on platforms that are not [officially supported][faq].

### Headless Ubuntu

If you're having trouble getting Binary Ninja installed in a headless server install where you want to be able to X-Forward the GUI on a remote machine, the following should meet requiremetns (for at least 14.04 LTS):

```
apt-get install libgl1-mesa-glx libfontconfig1 libxrender1 libegl1-mesa libxi6 libnspr4 libsm6
```

### Arch Linux

 - Install python2 from the [official repositories][archrepo] (`sudo pacman -S python2`) and create a sym link: `sudo ln -s /usr/lib/libpython2.7.so.1.0 /usr/lib/libpython2.7.so.1`
 - Install the [libcurl-compat] library with `sudo pacman -S libcurl-compat`, and run Binary Ninja via `LD_PRELOAD=libcurl.so.3 ~/binaryninja/binaryninja`

### KDE

To run Binary Ninja in a KDE based environment, set the `QT_PLUGIN_PATH` to the `QT` sub-folder:

```
cd ~/binaryninja
QT_PLUGIN_PATH=./qt ./binaryninja
```

### Debian

For Debian variants that (Kali, eg) don't match packages with Ubuntu LTS or the latest stable, the following might fix problems with libssl and libcrypto:

```
$ cd binaryninja
$ ln -s plugins/libssl.so libssl.so.1.0.0
$ ln -s plugins/libcrypto.so libcrypto.so.1.0.0
```

Alternatively, you might need to (as root):

```
apt-get install libssl-dev
ln -s /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.2 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
ln -s /usr/lib/x86_64-linux-gnu/libssl.so.1.0.2 /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0
```

### Gentoo

One Gentoo user [reported][issue672] a failed SSL certificate when trying to update. The solution was to copy over `/etc/ssl/certs/ca-certificates.crt` from another Linux distribution.

### NixOS

Here's a customer-provided nix derivation file for the Binary Ninja demo. Adapt as necessary for other versions, or hop onto our slack (specifically the #unsupported-distros channel) to find out more:

```
{ stdenv, autoPatchelfHook, makeWrapper, fetchurl, unzip, libGL, glib, fontconfig, xlibs, dbus, xkeyboard_config }:
stdenv.mkDerivation rec {
  name = "binary-ninja-demo";
  buildInputs = [ autoPatchelfHook makeWrapper unzip libGL stdenv.cc.cc.lib glib fontconfig xlibs.libXi xlibs.libXrender dbus ];
  src = fetchurl {
    url = "https://cdn.binary.ninja/installers/BinaryNinja-demo.zip";
    sha256 = "1yq2kgrhrwdi7f66jm1w5sc6r49hdhqnff9b0ysr5k65w9kxhl1k";
  };
  
  buildPhase = ":";
  installPhase = ''
    mkdir -p $out/bin
    mkdir -p $out/opt
    cp -r * $out/opt
    chmod +x $out/opt/binaryninja
    makeWrapper $out/opt/binaryninja \
          $out/bin/binaryninja \
          --prefix "QT_XKB_CONFIG_ROOT" ":" "${xkeyboard_config}/share/X11/xkb"
  '';
}
```

## API

 - If the GUI launches but the license file is not valid when launched from the command-line, check that you're using the right version of Python. Only a 64-bit Python 2.7 is supported at this time. Additionally, the [personal][purchase] edition does not support headless operation.

[known issues]: https://github.com/Vector35/binaryninja-api/issues?q=is%3Aissue
[libcurl-compat]: https://www.archlinux.org/packages/community/x86_64/libcurl-compat/
[archrepo]: https://wiki.archlinux.org/index.php/Official_repositories
[recover]: https://binary.ninja/recover.html
[support]: https://binary.ninja/support.html
[faq]: https://binary.ninja/faq.html
[purchase]: https://binary.ninja/purchase.html
[issue672]: https://github.com/Vector35/binaryninja-api/issues/672
