# Troubleshooting

## Basics

 - Have you searched [known issues]?
 - Is your computer powered on?
 - Did you read all the items on this page?
 - Then you should contact [support]!

## License Problems

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely un-install and re-download the latest installer. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](/getting-started/index.html#license).
- If you need to change the email address on your license, contact [support].

## Linux

Given the diversity of Linux distributions, some work-arounds are required to run Binary Ninja on platforms that are not [officially supported][faq].

### Arch Linux

 - Install python2 from the [official repositories][archrepo]
 - Install the [libcurl-compat] library from AUR, and run Binary Ninja via `LD_PRELOAD=libcurl.so.3 ~/binaryninja/binaryninja`

### KDE

To run Binary Ninja in a KDE based environment, set the `QT_PLUGIN_PATH` to the `QT` sub-folder:

```
cd ~/binaryninja
QT_PLUGIN_PATH=./qt ./binaryninja
```


## API

 - If the GUI launches but the license file is not valid when launched from the command-line, check that you're using the right version of Python. Only a 64-bit Python 2.7 is supported at this time. Additionally, the [personal][purchase] edition does not support headless operation.

[known issues]: https://github.com/Vector35/binaryninja-api/issues?q=is%3Aissue
[libcurl-compat]: https://aur.archlinux.org/packages/libcurl-compat/
[archrepo]: https://wiki.archlinux.org/index.php/Official_repositories
[recover]: https://binary.ninja/recover.html
[support]: https://binary.ninja/support.html
[faq]: https://binary.ninja/faq.html
[purchase]: https://binary.ninja/purchase.html
