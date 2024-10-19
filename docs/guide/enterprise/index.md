# Binary Ninja Enterprise

!!! note
    This section only applies to the Ultimate edition of Binary Ninja.

The Ultimate edition of Binary Ninja seamlessly integrates remote collaboration functionality, provided by the Binary Ninja Enterprise server, within the client. This includes remote project management, push/pull of analysis database and type archive snapshots, real-time chat, and more.


## Licensing

Starting Ultimate for the first time, you will be greeted by the following dialog:

![License Dialog](../../img/enterprise/license-dialog.png){: style="max-width:500px; display: block; margin: auto;"}

If you have a *named* license, your experience should be identical to that of a Commercial edition build, but with the additional features of Ultimate. Click the "Used Named License..." button and select the `license.dat` that was provided when you purchased your license. This will be placed in your [user folder](../index.md#user-folder).

Otherwise, you will need to check out a *floating* license from your Enterprise server. Enter your server location into the box and click "Connect". (All connections should happen over HTTPS and the default port is 3535.)

## Authentication

When connecting to an Enterprise server, you will see the following dialog:

![Login Dialog](../../img/enterprise/login-dialog.png){: style="max-width:432px; display: block; margin: auto;"}

This dialog will have up to 5 fields:

* **Server**: The Enterprise server you are connecting to, which can be changed by clicking the edit icon to the right. (This will cause Binary Ninja to restart.)
* **Authentication**: If the Enterprise server you are connecting to has a Single Sign-On (SSO) provider configured, this drop-down menu will appear to allow users to authenticate via SSO instead of username and password.
* **Username**: This text box contains your username if you are logging in with an Enterprise server account (hidden if using SSO).
* **Password**: This text box contains your password if you are logging in with an Enterprise server account (hidden if using SSO).
* **Remember Me**: This checkbox will remember the settings you choose and try to log you in the same way in the future.
* **Checkout Duration**: This drop-down provides a selection of license durations. The default is "Until I Quit", which will refresh your license every 15 minutes until you quit Binary Ninja.

## Configuration

Binary Ninja has a number of settings that let you change how it connects to and uses the Enterprise server. These settings can be found in the main Settings window (`Edit -> Preferences`) within Binary Ninja. See the [Settings](../settings.md) documentation for more details.

## User Interface

The Ultimate edition of Binary Ninja adds a few extra items in the user interface. These include:

* An extra [status indicator](#status-indicator) in the status bar
* The [Remote Dialog](#remote-dialog)
* The [Chat](#chat) sidebar widget
* The [User Positions](#user-positions) sidebar widget
* The [Describe Changes](#describe-changes-dialog) and [Resolve Merge Conflict](#resolve-merge-conflict-dialog) dialogs

### Status Indicator
The first additional UI feature can be found in the bottom-left corner of the status bar:

![Status Bar](../../img/enterprise/status-bar.png){: style="max-width:324px; display: block; margin: auto;"}

This indicator consists of three separate sections: The active server button, the sync button, and the project button.

#### Active Server Button
This button shows your connection status with the Enterprise server and acts as a shortcut to the Remote Dialog.

#### Sync Button
This button shows how many snapshots can be pushed to or pulled from the Enterprise server. It is only shown with a shared database open. Clicking it will push and pull snapshots as needed to synchronize your local state with the Enterprise server's state. This is the best way to quickly share your changes with other collaborators and ensure you have their changes, too.

The sync button has four indicators, some of which may be hidden:

* `!!`: This indicates that there has been a problem with either getting status from the server or syncing with the server. Check the log for more details.
* `# ↑`: This indicates the number of local snapshots that have not yet been pushed to the Enterprise server.
  * If you see a `*` next to the number, that indicates that you have unsaved local changes that are not yet part of a snapshot.
  * If this indicator is missing, it means your user does not have permission to push snapshots to the Enterprise server for this file.
* `# ↓`: This indicates the number of remote snapshots that have not yet been pulled from the Enterprise server.
* `↻`: This indicates that Binary Ninja is in the process of checking with the Enterprise server to see if there are any new snapshots available.

!!! note
    Clicking this button will cause a save to occur. It's not possible to sync without having all changes in a snapshot, which requires a save.

#### Project Button
This button shows the currently active project and will show the Project Browser tab when clicked. See the main Binary Ninja documentation for more information regarding projects.

### Remote Dialog
The Remote Dialog is the primary point of interaction with a remote Enterprise server. It can be opened by:

* Clicking on the active server button in the status bar (see above)
* Clicking `View/Collaboration/Remote Dialog` in the menu bar
* Opening the command palette (`[CTRL/CMD-P]`) and choosing `Collaboration - Remote Dialog` in the list

![Remote Dialog](../../img/enterprise/remote-dialog.png){: style="max-width:707px; display: block; margin: auto;"}

The main components of the Remote Dialog window deal with management and display of remote projects. On top of these is an area for managing the server and your connection to it.

#### Project List
The Project List shows what projects are available to you on the Enterprise server. Right-click will give a context menu with the following options:

* **Manage Permissions**: Opens a dialog where you can manage permissions for the project
* **Edit Info**: Opens a dialog where you can edit project metadata
* **Delete**: Deletes the project (this has a confirmation dialog and is *non-recoverable*)
* **Add Project**: Opens a dialog where you can add project metadata for a new project

![Project Metadata Dialog](../../img/enterprise/project-metadata.png){: style="max-width:461px; display: block; margin: auto;"}

#### Manage Permissions Dialog
![Manage Permissions Dialog](../../img/enterprise/manage-permissions.png){: style="max-width:657px; display: block; margin: auto;"}

Permissions can be set on *users* or *groups* of users. Available permissions are:

* **View**: Lets the user or group view the files in the project, but not push any changes
* **Edit**: Lets the user or group push analysis changes, upload files, and change product details, in addition to view permissions
* **Admin**: Lets the user or group modify the project permissions, in addition to edit permissions

#### Server Area
Across the of the Remote Dialog are five buttons:

* **Refresh**: Refreshes the projects and files shown from the currently active server.
* **Connect**/**Disconnect**: Connects to (or disconnect from) an Enterprise server. If connecting, it will show the "Connect to Remote" window (see below).
* **Manage Users...**: Opens a dialog that allows adding, editing, and removing users from the current server. (Only available to server administrators.)
* **Manage Groups...**: Opens a dialog that allows adding, editing, and removing groups from the current server. (Only available to server administrators.)
* **Actions**: Opens a context menu with the following options:
  * **Create Project...**: Opens a dialog box for creating a new project.
  * **Import Local Project...**: Opens a file picker to select a local project to upload in its entirety.
  * **Edit Properties...**: Opens a dialog box for editing the current project's name and description.
  * **Manage Permissions...**: Opens a dialog for editing the current project's permissions.
  * **Delete...**: Deletes the currently selected project. This has a confirmation dialog and is *non-recoverable*!

Above these buttons is your current server connection status.

#### Connect to Remote Window
The "Connect to Remote" window is shown when the Connect button is clicked. Here, you can manage Enterprise servers with the buttons on the right of the window.

![Connect to Remote](../../img/enterprise/connect-to-remote.png){: style="max-width:429px; display: block; margin: auto;"}

When connecting to a new Enterprise server, a Login dialog will appear. In addition to the obvious username and password fields, the `Remember me` field will store a token in your platform's secret store or keychain. `Automatically connect` will attempt to reconnect to this Enterprise server in the future.

### Chat
Every file in a project has an associated chat log that can be accessed via the Chat sidebar icon. Users working on the same file can send messages in the chat window to communicate with other collaborators in real-time.

![Chat Sidebar Widget](../../img/enterprise/chat-sidebar-widget.png){: style="max-width:344px; display: block; margin: auto;"}

### User Positions
Every file in a project has an associated list of user positions that can be accessed via the User Positions sidebar icon. This is a table that shows, in real-time:

* **Username**: The username of users that have this file open from the server
* **View Type**: The type of view each user is currently looking at
* **Function**: The function each user is looking at, if they are looking at a function
* **Offset**: The offset in the file each user is looking at
* **IL Type**: What type of IL each user is looking at

Double-clicking on any entry in this table will navigate you to that location within the file.

![User Positions Widget](../../img/enterprise/user-positions-sidebar-widget.png){: style="max-width:342px; display: block; margin: auto;"}

### Describe Changes Dialog
In any open file from a shared project, the Describe Changes Dialog will appear during the sync process if you are pushing any changes to the Enterprise server. This will apply a name to the set of changes you are pushing and add an entry in the file's Changelog.

![Describe Changes Dialog](../../img/enterprise/describe-changes.png){: style="max-width:335px; display: block; margin: auto;"}

### File Changelog
The File Changelog can be accessed via `File/Collaboration/File Changelog...`. It shows a list of changes that have been made to the current file, along with what user made those changes, when, and a description of those changes. Items in this list are *sets* of changes (typically all of the changes before a user clicked the sync button), rather than every snapshot in the database.

![File Changelog](../../img/enterprise/file-changelog.png){: style="max-width:901px; display: block; margin: auto;"}

### Resolve Merge Conflict Dialog
If any conflicts arise while you are syncing your changes to the Enterprise server, the Resolve Merge Conflict Dialog will appear.

![Resolve Merge Conflict Dialog](../../img/enterprise/merge-conflict.png){: style="max-width:816px; display: block; margin: auto;"}

The left-hand side of the dialog will show the conflicts in a list. The right-hand side of the dialog will show the conflict. The buttons along the bottom can be used to:

* **Choose Left**: Choose to keep the change on the left for this conflict
* **Choose Right**: Choose to keep the change on the right for this conflict
* **Choose All Left**: Choose to keep the changes on the left for all conflicts
* **Choose All Right**: Choose to keep the changes on the right for all conflicts
* **Cancel Merge**: Stop syncing and return to the latest snapshot without merging

## API Examples

Examples of using the `collaboration` and `enterprise` APIs (which are unique to the Ultimate edition) can be found bundled with your installation:

* **macOS**: `Binary\ Ninja.app/Contents/Resources/python/binaryninja/collaboration/examples`
* **Linux**: `binaryninja/python/binaryninja/collaboration/examples`
* **Windows**: `Binary Ninja\python\binaryninja\collaboration\examples`
