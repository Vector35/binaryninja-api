# Privacy

Binary Ninja is designed with user privacy in mind. During normal operation, **no binary data from files you are analyzing is sent to any server**. This page documents every category of network communication that Binary Ninja may perform, what data is transmitted, and how to disable each one.

**Scope:** This privacy policy applies only to the downloadable, paid editions of Binary Ninja. Third-party plugins and the free demo edition may have different data collection practices and are not covered by this policy.

## Data Usage

The data described on this page is used only for two purposes:

1. **Directly operating the requested service** — for example, checking whether an update is available, downloading a plugin, or looking up a function signature.
2. **Aggregate demographic information** — such as understanding which operating systems, platforms, and architectures are actively in use so we can make informed decisions about adding or removing support for them.

Data is never sold or shared with third parties, and is never used to identify or profile individual users beyond what is necessary to provide the services described below.

## Update Checking

By default, Binary Ninja periodically checks for software updates.

**Data sent to `master.binary.ninja`:**

- Product name
- License serial number
- Update signature (a cryptographic key used to verify update eligibility)
- Current Binary Ninja version
- Platform (e.g., `linux`, `macos`, `windows`)
- CPU architecture (e.g., `x86_64`, `arm64`)
- OS major version number
- Linux distribution name (Linux only)
- Your external IP is included in the webserver logs but not explicitly included in the update request

A separate license expiration check sends only the license serial number.

All three of the settings below use the same update server endpoint and send the same data listed above. The results are cached briefly, so whichever feature triggers the request first will serve the others from cache, but any of them can initiate the connection. To prevent all update-related network requests, all three must be disabled.

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `network.enableUpdates` | `true` | Automatically check for updates on startup |
| `network.enableUpdateChannelList` | `true` | Fetch available update channels (used in preferences) |
| `network.enableReleaseNotes` | `true` | Fetch release notes for display on the new tab page |

## Extension Manager

The extension manager contacts `extensions.binary.ninja` to fetch plugin metadata and download plugins.

**Data sent:**

- Standard HTTPS request headers
- When using short URLs for plugin downloads (enabled by default), download counts are tracked by the server

No personal data or information about your analysis is transmitted.

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `network.enableExtensionManager` | `true` | Master switch for all extension manager networking |
| `extensionManager.officialRepo` | `true` | Enable official plugin repository |
| `extensionManager.communityRepo` | `true` | Enable community plugin repository |

Setting `network.enableExtensionManager` to `false` disables all extension manager network requests.

## PDB Symbol Downloads

When analyzing Windows binaries, Binary Ninja can automatically download PDB debug symbol files from Microsoft's public symbol server (or other configured servers).

**Data sent to symbol servers:**

- PDB identifier (GUID and age from the PE header)
- PDB filename

This information is derived from the binary being analyzed and is sent to whichever symbol servers are configured.

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `network.pdbAutoDownload` | `true` | Automatically search for and download PDB files |
| `pdb.files.symbolServerList` | `["https://msdl.microsoft.com/download/symbols"]` | List of symbol servers to query |

Setting `network.pdbAutoDownload` to `false` prevents automatic PDB downloads.

## Crash Reporting

Binary Ninja includes an optional crash reporting system powered by Sentry/Crashpad. **Crash reporting is disabled by default in paid editions.**

When enabled, crash reports are sent only if Binary Ninja crashes, and include:

- Stack traces at the time of the crash
- System information (OS version, CPU architecture)
- Binary Ninja version and edition
- Loaded module names and addresses

Crash reports **do not** include:

- Contents of files being analyzed
- User documents or project data
- Personal information

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `crashReporting.enabled` | `false` | Enable crash reporting (requires restart) |

Crash reporting can also be controlled via environment variables: set `BN_DISABLE_CRASH_REPORTING` to force it off, or `BN_ENABLE_CRASH_REPORTING` to force it on regardless of the setting.

## WARP (Function Signature Matching)

WARP is Binary Ninja's function signature matching system. It can operate entirely locally using bundled signature files, or optionally connect to a network server for additional signatures.

**Network functionality is disabled by default.** No WARP network requests are made unless you explicitly enable the `network.enableWARP` setting and restart Binary Ninja. Even once enabled, the only automatic network activity is fetching known function signatures from the server during analysis. All uploads of signature data require explicit user action.

**Data sent to `warp.binary.ninja` (when network is enabled):**

- Function GUIDs (128-bit identifiers derived from function bytecode)
- Platform and architecture of the binary being analyzed (e.g., `windows-x86_64`)

Function GUIDs are computed from the byte content of functions and are used to look up known function names and type information. No raw binary content is transmitted, however it would be possible to match against a copy of the same file to know if the same file is being analyzed.

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `network.enableWARP` | `false` | Master switch for WARP network requests (requires restart) |
| `warp.container.serverUrl` | `https://warp.binary.ninja` | Primary WARP server URL |
| `warp.container.serverApiKey` | (empty) | API key for authenticated access |

## External URLs

Binary Ninja can open files from external URLs using the menu. This requires explicit user interaction.

**Settings to disable:**

| Setting | Default | Description |
|---------|---------|-------------|
| `network.enableExternalUrls` | `true` | Allow opening external URLs |

## Network Monitoring

For full visibility into all network requests Binary Ninja makes, you can enable download logging:

| Setting | Default | Description |
|---------|---------|-------------|
| `network.logDownloads` | `false` | Log all URLs accessed by the download provider |

Setting `network.logDownloads` to `true` will log every URL that Binary Ninja contacts to the log console. You can also set the environment variable `BN_DEBUG_TRACE_NETWORK=1` for even more detailed network tracing with stack traces.

## Proxy Configuration

All network requests respect your system's proxy settings. You can also configure a proxy explicitly:

| Setting | Default | Description |
|---------|---------|-------------|
| `network.httpsProxy` | (empty) | Override HTTPS proxy (auto-detected by default) |

## Disabling All Network Access

To completely prevent Binary Ninja from making any network requests, set the following:

```json
{
    "network.enableUpdates": false,
    "network.enableUpdateChannelList": false,
    "network.enableReleaseNotes": false,
    "network.enableExtensionManager": false,
    "network.pdbAutoDownload": false,
    "network.enableExternalUrls": false,
    "network.enableWARP": false,
    "crashReporting.enabled": false
}
```

Note that for non-floating licenses, license validation is performed locally and does not require network access.
