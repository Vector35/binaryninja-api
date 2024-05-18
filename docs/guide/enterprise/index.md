# Binary Ninja Enterprise Client

!!! note
    This section only applies to the `Enterprise` edition of Binary Ninja

Welcome to the Binary Ninja Enterprise client documentation, part of our Binary Ninja Enterprise product.

### Licensing

If your Enterprise client came with a *named* license, please ensure the `license.dat` that contains the license has been placed in your user folder. User folder locations, per platform, are:

* Windows: `%APPDATA%\Binary Ninja`
* macOS: `~/Library/Application Support/Binary Ninja`
* Linux: `~/.binaryninja`

Otherwise, the Enterprise client will need to check out a *floating* license from the server. This happens while you are logging in (unless you already have a license) and will automatically renew based on the "Checkout Duration" interval you chose in the login dialog.

## API Examples

Examples of using the `collaboration` and `enterprise` APIs (which are unique to the Enterprise edition of the client) can be found bundled with the client:

* **macOS**: `Binary\ Ninja.app/Contents/Resources/python/binaryninja/collaboration/examples`
* **Linux**: `binaryninja/python/binaryninja/collaboration/examples`
* **Windows**: `Binary Ninja\python\binaryninja\collaboration\examples`

## Configuration

The Enterprise client has a number of user-configurable settings that let you change its behavior. These settings can be found in the main Settings window (`Edit -> Preferences`) within Binary Ninja in two separate areas:

### Collaboration

* *Active Server* (`collaboration.activeRemote`) is the URL of the Enterprise server to automatically connect to on launch.
* *Advanced Conflict Resolution* (`collaboration.advancedMerge`) shows additional information in the merge conflict resolution UI.
* *Auto Connect* (`collaboration.autoConnectOnLaunch`) makes Binary Ninja attempt to connect to your last used Enterprise server when you open the application.
* *Poll Interval* (`collaboration.autoPollInterval`) controls the time between automatic fetching for updated snapshots from the Enterprise server. This updates the pending change counts shown on the sync button in the status bar, but does not pull the changes. Set this to 0 to disable polling entirely.
* *Collaboration Project Directory* (`collaboration.directory`) defines the directory on your local disk where local copies of Collaboration files will be stored.
* *Maximum Conflict Diff Size* (`collaboration.maxConflictDiff`) defines a maximum size for showing diffs, which prevents performance issues with large diffs
* *Collaboration Servers* (`collaboration.servers`) is a list of Enterprise servers and their URLs that the Enterprise client may connect to.
* *Sync on Save* (`collaboration.syncOnSave`) controls whether the Enterprise client will sync your local changes to the Enterprise server every time you save.

### Enterprise

* *Automatically Checkout License* (`enterprise.autoCheckout`), if enabled, will cause Binary Ninja Enterprise to automatically check out a license on launch.
* *Default License Checkout Duration* (`enterprise.defaultCheckoutDuration`) will change the default duration of a checked out license.
* *Secrets Provider* (`enterprise.secretsProvider`) will change the secrets provider used for storing your checked out license.
* *Enterprise Server URL* (`enterprise.server.url`) is a read-only setting that shows the base URL for the currently connected Enterprise server.

### Core

* *Collaboration Plugin* (`corePlugins.collaboration`) allows you to disable all collaboration features.
* *Database Viewer (Debug)* (`corePlugins.databaseViewer`) enables an experimental, built-in database viewer plugin that can be used to debug database issues.

### Network

* *Enable Collaboration Server* (`network.enableCollaborationServer`) controls all collaboration network activity.

### Updates

* *Use Enterprise Server For Updates* (`updates.useEnterpriseServer`) controls whether the client will look for updates on the internet from the official Binary Ninja update servers (unchecked) or from the currently connected Enterprise server (checked).
