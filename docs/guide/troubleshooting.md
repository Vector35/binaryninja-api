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

## Plugin Troubleshooting

While third party plugins are not officially supported, there are a number of troubleshooting tips that can help identify the cause. The most importat is to enable debug logging as suggested in the previous section. This will often highlight problems with python paths or any other issues that prevent plugins from running.

## License Problems

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely un-install and [recover][recover] the latest installer and license. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](/getting-started/index.html#license).
- If you need to change the email address on your license, contact [support].

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
$ cd binaryninja/plugins
$ ln -s libssl.so libssl.so.1.0.0
$ ln -s libcrypto.so libcrypto.so.1.0.0
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
