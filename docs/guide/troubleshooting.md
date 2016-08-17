# Troubleshooting

## Basics

 - Have you searched [known issues]?
 - Is your computer powered on?
 - Did you read all the items on this page?
 - Then you should contact [support]!

### License Trouble

- If experiencing problems with Windows UAC permissions during an update, the easiest fix is to completely un-install and re-download the latest installer. Preferences are saved outside the installation folder and are preserved, though you might want to remove your [license](/getting-started/index.html#license).

## Arch Linux

Arch Linux is not an officially supported operating system, but many of our users have run it, and there are a few pitfalls to watch out for.

 - Install python2 from the [official repositories][archrepo]
 - Install the [libcurl-compat] library from AUR, and run Binary Ninja via `LD_PRELOAD=libcurl.so.3 ~/binaryninja/binaryninja`

## API

 - If the GUI launches but the license file is not valid, check that you're using the right version of Python. Only a 64-bit Python 2.7 is supported at this time.

[known issues]: https://github.com/steakknife/unsign
[libcurl-compat]: https://aur.archlinux.org/packages/libcurl-compat/
[archrepo]: https://wiki.archlinux.org/index.php/Official_repositories
[recover]: https://binary.ninja/recover.html
[support]: https://binary.ninja/support.html
