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

## Troubleshooting Plugins

### Disabling Plugins

Disabling plugins can be a quick way to diagnose whether some unexpected behavior is caused by Binary Ninja itself or a plugin. Simply launch the process with the extra command-line option `-p` to disable all user plugins at load time. Note that repository plugins are currently not disabled with this switch.

### Other Steps

While third party plugins are not officially supported, there are a number of troubleshooting tips that can help identify the cause. The most important is to enable debug logging as suggested in the previous section. This will often highlight problems with python paths or any other issues that prevent plugins from running.

Additionally, if you're having trouble running a plugin in headless mode (without a GUI calling directly into the core), make sure you're running the Commercial version of Binary Ninja as the Student/Non-Commercial edition does not support headless processing.

Next, if running a python plugin, make sure the python requirements are met by your existing installation. Note that on windows, the bundled python is used and python requirements should be installed either by manually copying the modules to the `plugins` [folder](/getting-started/#directories).

## License Problems

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely un-install and [recover][recover] the latest installer and license. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](/getting-started/#license).
- If you need to change the email address on your license, contact [support].

## Platforms

The below steps are specific to different platforms that Binary Ninja runs on.  See the [FAQ] for currently supported versions.

## API

 - If the GUI launches but the license file is not valid when launched from the command-line, check that you're using the right version of Python as only 64-bit Python 2.7, or 3.x versions are supported. Additionally, the [personal][purchase] edition does not support headless operation.


## Database Issues

 - BNDBs may grow in size after repeated saving/loading. While a future update to Binary Ninja will implement this optimization internally, this [unofficial script] may be useful for shrinking the size of a BNDB. Please ensure you backup your database prior to trying that script as it is not an officially supported operation.

### Windows

- While Windows 7 is not officially supported (by us, or Microsoft for that matter), it's possible to have Binary Ninja work if all available windows updates are installed as a library pack update somewhere in the updates is required for us to run.
- If you install Windows without internet access and have never run windows updates to install an update, you may have an incomplete windows certificate store. You'll see errors when attempting to update about `CERTIFICATE VERIFICATION FAILED`.  If that is the case, you can either use something like `certutil.exe -generateSSTFromWU roots.sst` and then manually copy over the DST and Amazon certificates into your root store, or wait until the next time you have an update from Windows Update which should automatically refresh your certificate store. 


### OS X

While OS X is generally the most trouble-free environment for Binary Ninja, very old versions may have problems with the RPATH for our binaries and libraries. There are two solutions. First, run Binary Ninja with: 

```
DYLD_LIBRARY_PATH="/Applications/Binary Ninja.app/Contents/MacOS" /Applications/Binary\ Ninja.app/Contents/MacOS/binaryninja
```

Or second, modify the binary itself using the [install_name_tool](https://blogs.oracle.com/dipol/dynamic-libraries,-rpath,-and-mac-os).

#### Non-brew installed Python 3

One potential issue for installed Python 3.x versions on MacOS is that the bundled certificates do not align with the native certificate store. This results in an erorr while attempting to download updates using the python provider. One of the following may fix this:

```
pip install --upgrade certifi
```

or:

```
open /Applications/Python\ 3.6/Install\ Certificates.command
```

### Linux

Given the diversity of Linux distributions, some work-arounds are required to run Binary Ninja on platforms that are not [officially supported][FAQ].

#### Headless Ubuntu

If you're having trouble getting Binary Ninja installed in a headless server install where you want to be able to X-Forward the GUI on a remote machine, the following should meet requirements (for at least 14.04 LTS):

```
apt-get install libgl1-mesa-glx libfontconfig1 libxrender1 libegl1-mesa libxi6 libnspr4 libsm6
```

#### Arch Linux

 - The only known issues with Arch linux are related to not being able to automatically find the appropriate libpython. Specifying your own custom path to the `libpython.so` in the [Advanced Settings](../getting-started.md#advanced-settings) dialog under the `Python Interpreter` setting should solve any issues.

#### KDE

To run Binary Ninja in a KDE based environment, set the `QT_PLUGIN_PATH` to the `QT` sub-folder:

```
cd ~/binaryninja
QT_PLUGIN_PATH=./qt ./binaryninja
```

#### NixOS

Here's a customer-provided nix derivation file for the Binary Ninja demo. Note that you'll likely want to update the SHA256 field with the latest value available [here](https://binary.ninja/js/hashes.js).  Adapt as necessary for other versions, or hop onto our slack (specifically the #unsupported-distros channel) to find out more:

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

[known issues]: https://github.com/Vector35/binaryninja-api/issues?q=is%3Aissue
[libcurl-compat]: https://www.archlinux.org/packages/community/x86_64/libcurl-compat/
[archrepo]: https://wiki.archlinux.org/index.php/Official_repositories
[recover]: https://binary.ninja/recover.html
[support]: https://binary.ninja/support.html
[FAQ]: https://binary.ninja/faq.html
[purchase]: https://binary.ninja/purchase.html
[unofficial script]: https://gist.github.com/0x1F9F1/64725fbe9acdeafaf39e048e03f4dd9d
