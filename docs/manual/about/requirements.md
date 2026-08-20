# Requirements

One Binary Ninja license covers Linux, macOS, and Windows.

## Supported Platforms

| Platform | Versions | Architectures |
|----------|----------|---------------|
| Linux | Ubuntu 24.04 and 26.04 | x64, arm64 |
| macOS | macOS 15 (Sequoia) and 26 (Tahoe) | x64, arm64 |
| Windows | Windows 10 and Windows 11 | x64 |

These are the versions we test against. Older releases often work, they're just not tested or supported.

Other Linux distributions, including Ubuntu flavors like Kubuntu and rolling-release distributions like Arch, generally work but are unofficially supported. The main constraint is the system glibc version — see [glibc Version Requirements](../guide/troubleshooting.md#glibc-version-requirements) for the current baseline.

We generally support the latest version of each platform plus the most recent long-term supported version prior to that.

## Minimum System Requirements

| Resource | Minimum |
|----------|---------|
| CPU | 2 GHz, multi-core |
| RAM | 8 GB |
| Free disk space | 4 GB |

Binary Ninja may work with less than the above, but this is what is officially supported. Try the [free edition](https://binary.ninja/free/) first if you have concerns.

## Python

Binary Ninja requires Python 3.10 or above. A Python build without GPL components is shipped with Windows builds; other platforms use an existing Python install.

## CPU Architectures and File Formats

Binary Ninja includes varying levels of support for different CPU architectures and file formats depending on the edition. The [purchase page](https://binary.ninja/purchase/) has a table of which are available in each edition. [Extended Support Contracts](https://binary.ninja/support/extended.html) are available to add architectures or formats that aren't listed.

## Enterprise Server

Any licensed copy of Binary Ninja Ultimate (named, computer, or floating) can connect to an Enterprise server, on any of the platforms listed above.

Requirements for the Enterprise server itself are documented separately in the [Enterprise documentation](https://docs.enterprise.binary.ninja/#requirements).
