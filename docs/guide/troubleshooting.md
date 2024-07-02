# Troubleshooting

## Basics

 - Have you searched [known issues]?
 - Have you tried rebooting? (Kidding!)
 - Did you read all the items on this page?
 - Then you should contact [support]!

## Bug Reproduction
Running Binary Ninja with debug logging will make your bug report more useful.

``` bash
./binaryninja --debug --stderr-log
```

Alternatively, it might be easier to save debug logs to a file instead:

``` bash
./binaryninja -d -l logfile.txt
```

(note that both long and short-form of the command-line arguments are demonstrated in the above examples)

## Troubleshooting Plugins

### Disabling Plugins

Disabling plugins can be a quick way to diagnose whether some unexpected behavior is caused by Binary Ninja itself or a plugin. Simply launch the process with the extra command-line option `-p` to disable all user plugins at load time. Note that repository plugins are currently not disabled with this switch.


### Disabling User Settings

In addition to the above-mentioned method of disabling user-plugins, you can also set the environment variable `BN_DISABLE_USER_PLUGINS` (the value doesn't matter, the mere existence of the variable is enough). Related, there is another setting: `BN_DISABLE_USER_SETTINGS` that will launch BN without relying on any user settings which is useful for identifying whether a particular behavior is the result of a setting without having to manually change a number of settings.

### Other Steps

While third party plugins are not officially supported, there are a number of troubleshooting tips that can help identify the cause. The most important is to enable debug logging as suggested in the previous section. This will often highlight problems with python paths or any other issues that prevent plugins from running.

Additionally, if you're having trouble running a plugin in headless mode (without a GUI calling directly into the core), make sure you're running the Commercial version of Binary Ninja as the Student/Non-Commercial edition does not support headless processing.

Next, if running a python plugin, make sure the python requirements are met by your existing installation. Note that on Windows, the bundled python is used and python requirements should be installed either by manually copying the modules to the `plugins` [folder](./index.md#directories), or by switching to a different interpreter in the settings.

## License Problems

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely uninstall and [recover][recover] the latest installer and license. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](./index.md#license).
- If you need to change the email address on your license, contact [support].

## Running as Root

Binary Ninja will refuse to run as root on Linux and macOS platforms. You can work around this issue by either running as a regular user, or forcing BN to launch. If you try to use `su` or another similar tool, make sure that user has permission to the X11 session.

## API

 - If the GUI launches but the license file is not valid when launched from the command-line, check that you're using the right version of Python as only 64-bit Python 2.7, or 3.x versions are supported. Additionally, the [personal][purchase] edition does not support headless operation.

## Database Issues

 - BNDBs may grow in size after repeated saving/loading. To shrink the size of your database, use the `File` / `Save analysis database with options` menu and select one or both of the checkboxes.

## Platforms

The below steps are specific to different platforms that Binary Ninja runs on.  See the [FAQ] for currently supported versions.

### Windows

- While Windows 7 is not officially supported (by us, or Microsoft for that matter), it may work if all available Windows updates are installed (including non-security updates with certificate bundle updates).
- If you install Windows without internet access and have never run Windows updates to install an update, you may have an incomplete Windows certificate store. You'll see errors when attempting to update about `CERTIFICATE VERIFICATION FAILED`.  If that is the case, you can either use something like `certutil.exe -generateSSTFromWU roots.sst` and then manually copy over the DST and Amazon certificates into your root store, or wait until the next time you have an update from Windows Update which should automatically refresh your certificate store.

#### Some Graphics Chipsets

Some graphics chipsets may experience problems with [scaling](https://github.com/Vector35/binaryninja-api/issues/1529) resulting in the top menu disappearing. In that case, the simplest fix is to set the environment variable `QT_OPENGL=angle`.

#### VirtualBox and VMWare

If you're using Windows virtual machines within virtualbox or VMWare, you may have trouble with the 3d acceleration drivers. If so, disabling the 3d acceleration is the easiest way to get BN working.

You may also manually create a `settings.json` file in your [user folder](./index.md#user-folder) with the contents though using the [plugin manager](plugins.md#plugin-manager) may also have problems:

``` js
{
	"network.enableExternalResources" : false
}
```

### macOS

#### Ventura Code Signing

macOS Ventura enables more in-depth code signing verification that can cause issues with Binary Ninja when migrating between versions. If you receive a warning that `“Binary Ninja.app” is damaged and can’t be opened. You should move it to the Trash.`, it is likely that you have merely upgraded from an older version of Binary Ninja and older files in the application bundle are impacting code signing. The simplest fix is to simply request a [new download bundle](https://binary.ninja/recover/), drag the old bundle to the trash and drag the new bundle in place. Alternatively, if your bandwidth is low or you do not have an active license, you can try manually removing extra folders. In case you are migrating from 3.1.3439 to 3.2.3811, that would be:

```
rm -rf /Applications/Binary\ Ninja.app/Contents/Frameworks/Python.framework/Versions/3.9/
```

### Linux

Given the diversity of Linux distributions, some workarounds are required to run Binary Ninja on platforms that are not [officially supported][FAQ].

#### Common Problems

Below are a few of the most common problems with Linux installations:

 - Some unzip utilities do not maintain the `+x` executable bit on files when extracted. To fix this, we recommend:

 ```
 chmod +x binaryninja/*.so.*
 chmod +x binaryninja/plugins/*
 ```

 - Permissions: ensure that the user you are running Binary Ninja as has write permission to `~/.binaryninja` as it needs to be able to update user settings and other files in this folder.


#### Debian

Debian requires one package be manually installed to support the emoji icons used in the Tag system:

``` bash
apt install fonts-noto-color-emoji
```

#### Headless Ubuntu

If you're having trouble getting Binary Ninja installed in a headless server install where you want to be able to X-Forward the GUI on a remote machine, the following should meet requirements (for at least 14.04 LTS):

``` bash
apt-get install libgl1-mesa-glx libfontconfig1 libxrender1 libegl1-mesa libxi6 libnspr4 libsm6
```

#### Wayland

Binary Ninja uses X11 by default, but ships Wayland client support as an option. To enable Wayland support, run Binary Ninja with the following option:

``` bash
./binaryninja -platform wayland
```

Alternatively, you can set the `QT_QPA_PLATFORM` environment variable to `wayland`.

Wayland support in Binary Ninja is not complete, and has the following known issues:

* Panes cannot be dragged out into new windows. You must use the "New Window for Pane" action to move a pane into its own window.
* It is not possible to move panes between existing windows.
* In Gnome-based environments, the window decorations do not use the active theme, and are instead rendered using a Qt default.
* Font scaling settings may be ignored. You may have to manually adjust font sizes in the Binary Ninja Settings if you use font scaling.

It is recommended that Gnome users continue to use the X11 version, but users of other environments may have a better experience with the Wayland client, especially when using high resolution monitors with scaling.

#### NixOS

Here's a customer-provided nix derivation file for the Binary Ninja demo. Note that you'll likely want to update the SHA256 field with the latest [hashes].  Adapt as necessary for other versions, or hop onto our slack (specifically the #unsupported-distros channel on our [slack]) to find out more:

``` js
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
[slack]: https://slack.binary.ninja
[hashes]: https://binary.ninja/js/hashes.js

### Intel 13th and 14th generation CPUs

As described in [issue 5449](https://github.com/Vector35/binaryninja-api/issues/5449), several users have reported unknown crashes due to a [known bug](https://www.theverge.com/2024/6/14/24178751/intel-raptor-lake-crash-fix-etvb-not-yet). The currently recommended work-around is to do a BIOS upgrade to microcode 0x125 or later.

## Environment Variables

The following environment variables may be helpful when troubleshooting issues:

| Environment Variable | Type | Description |
| --- | --- | ----------- |
| BN_LICENSE | File Contents (String) | This variable is useful for using Binary Ninja with a license passed from outside a docker image without storing the raw license file inside. [Must contain](https://github.com/Vector35/debugger/blob/dev/scripts/build.py#L195-L196) the full contents of the license file.  |
| BN_USER_DIRECTORY | Path (String) | This variable overrides the [default user folder](https://docs.binary.ninja/guide/index.html#user-folder) path. |
| BN_DISABLE_REPOSITORY_PLUGINS | Flag (True if exists) | This setting will only disable plugins installed via the plugin manager. |
| BN_DISABLE_USER_PLUGINS | Flag (True if exists) | This environment variable will disable all plugins loaded from the [plugins user folder](https://docs.binary.ninja/guide/index.html#user-folder). |
| BN_DISABLE_USER_SETTINGS | Flag (True if exists) | This flag will cause Binary Ninja to ignore any [`settings.json`](https://docs.binary.ninja/guide/settings.html).|
| BN_SCREENSHOT | Flag (True if exists) | This flag removes some small UI clutter to enable cleaner screenshots. |
| BN_DEBUG_HTTP | Flag (True if exists) | This flag enables additional debug logging of HTTP activity. |
| BN_DEBUG_EXCEPTION_TRACES | Flag (True if exists) | This variable includes stack traces when exceptions are handled (MacOS and Linux only). |
| BN_DEBUG_CLANG | Flag (True if exists) | If set, this flag adds additional debugging information to stdout from clang type parsing. |


## File Associations

With the addition of [projects](../guide/projects.md) and [type archives](../guide/types/typearchives.md), Binary Ninja now includes support for `.bnpr` (project folders, openable on MacOS), `.bnpm` (project metadata, openable on all platforms), and `.bnta` (type archives, openable on all platforms) file formats. If installed fresh, these file associations will automatically be created. However, when using the built-in updater, the association is not currently added. To manually create the association, use the following:

### MacOS file associations

1. Update to a version with support for the new extensions (builds 4860 or newer)
1. Run:

```
/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister -f -R -trusted "/Applications/Binary Ninja.app"
```

### Windows file associations

1. Double-click the file you're trying to open
1. Click "More Apps"
1. Scroll to the bottom and select "Look for another app on this PC"
1. Find wherever you installed Binary Ninja and select the main executable

(Make sure to leave the "Always use this app to open" checkbox selected)

### Linux file associations

1. Re-run the [`linux-setup.sh`](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/linux-setup.sh) script. The appropriate copy is available wherever you installed Binary Ninja inside the `scripts/` subfolder.
