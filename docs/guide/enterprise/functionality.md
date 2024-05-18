# Functionality

Most functionality in the Enterprise client is accessed from the [Remote Dialog](user-interface.md#remote-dialog), which is shown when clicking the Active Server Button in the bottom-left of the status bar.


## Managing Servers

### Add a New Server
1. Open the Remote Dialog
2. Click `Connect...`
3. Click `Add...`
4. Enter the server hostname / port, and a friendly name it will be displayed as
5. Click `Add`

### Remove an Existing Server
1. Open the Remote Dialog
2. Click `Connect...`
3. Choose the server you want to remove
4. Click `Remove...`
5. Click `Yes`

### Log Into a Server
1. Open the Remote Dialog
    1. If you have previously chosen `Remember Me`, you may be prompted for credentials as Binary Ninja checks for saved sessions
2. Click `Connect...`
3. Choose the Enterprise server you want to connect to
4. Click `Connect`
    1. If you have previously chosen `Remember Me` and are logged into this server, you will not see an authentication dialog before being connected
    2. If the server cannot be connected to, an error will be displayed in the log with details (click the error indicator on the window’s status bar to read the error)
    3. The Server ID mismatch dialog may appear if the server you are connecting to has changed in some way since you last connected to it
5. The authentication dialog will open for you to enter your username and password
    1. If you have forgotten or need to reset your password, click `Forgot Password` and follow the directions to be emailed a link to reset your password
    2. Optionally, check `Remember Me` if you want to save your login for the next time you open Binary Ninja
    3. Optionally, check `Automatically Connect` if you want to log in automatically every time you open Binary Ninja
6. Click `Login`
    1. If the login was successful, the authentication dialog will close, and the Remote Dialog will update to show your current Projects
    2. If you checked `Remember Me`, your session will be saved to your OS’s secure storage and can be cleared at any time by logging out of the Enterprise server
    3. If the login was unsuccessful, a dialog will display an error message with details

### Disconnecting From a Server
1. Open the Remote Dialog
2. Click `Disconnect...`

### Log Out of a Server
1. Open the Remote Dialog
    1. If you are currently connected to an Enterprise server, disconnect from it
2. Click `Connect...`
3. Choose the Enterprise server you want to log out of
4. Click `Log Out`
5. Click `Yes`


## Managing Users

### Create a New User
1. Open the Remote Dialog
2. Ensure you are logged into the server as an administrator.
3. Click `Manage Users...`
4. The Manage Users dialog will appear.
5. Click `Add...`
6. Fill out the details for the new user you want to create.

!!! note
    If you want to make the new user a server administrator, see the Binary Ninja Enterprise server documentation.

### Edit an Existing User
1. Open the Remote Dialog
2. Ensure you are logged into the server as an administrator.
3. Click `Manage Users...`
4. The Manage Users dialog will appear.
5. Select the user whose details you want to edit.
6. Click `Edit...`
7. Fill in the new details for this user

!!! note
    If you want to make the new user a server administrator, see the Binary Ninja Enterprise server documentation.

### Disable an Existing User
Users cannot be deleted from the Enterprise server since this would break our ability to keep attribution on stored snapshots. Users can, however, be disabled. Disabled users are unable to authenticate with an Enterprise client or with the Enterprise server.

1. Open the Remote Dialog
2. Ensure you are logged into the server as an administrator
3. Click `Manage Users...`
4. The Manage Users dialog will appear
5. Select the user to remove
6. Click `Disable...`
7. Click `Yes`


## Managing Groups
### Create a New Group
1. Open the Remote Dialog
2. Ensure you are logged into the server as a server administrator.
3. Click `Manage Groups...`
4. The Manage Groups dialog will appear.
5. Click `Add...`
6. Move users between "Available" and "Chosen" as needed

### Edit an Existing Group
1. Open the Remote Dialog
2. Ensure you are logged into the server as an administrator.
3. Click `Manage Groups...`
4. The Manage Group dialog will appear.
5. Select the group you want to edit.
6. Click `Edit...`
7. Move users between "Available" and "Chosen" as needed

### Delete an Existing Group
1. Open the Remote Dialog
2. Ensure you are logged into the server as an administrator
3. Click `Manage Groups...`
4. The Manage Groups dialog will appear
5. Select the group to remove
6. Click `Delete...`
7. Click `Yes`


## Managing Projects

### Create a New Project
1. Open the Remote Dialog
2. Connect to an Enterprise server
3. Click `Actions` above the File List
4. In the Project List, click `Create Project...`
5. Enter a name and description for your new project
6. Click `Ok`

### Edit a Project's Details
1. Open the Remote Dialog
2. Connect to an Enterprise server
3. In the Project List, select the project whose details you want to edit
4. Click `Actions` above the File List
5. In the Project List, click `Edit Properties...`
6. Enter the name and description for the project
7. Click `Ok`

### Delete a Project
1. Open the Remote Dialog
2. Connect to an Enterprise server
3. In the Project List, select the project you want to delete
4. Click `Actions` above the File List
5. In the Project List, click `Delete...`
6. Click `Yes`

### Manage User or Group Permissions for a Project
!!! note
    If the `Manage Permissions...` action is disabled, your account is not marked as a Project Admin.

1. Open the Remote Dialog
2. Connect to an Enterprise server
3. In the Project List, select the project you want to modify
4. Click `Actions` above the File List
5. Click `Manage Permissions...` and the Project Permissions dialog will open

#### Add a User to a Project
From the Project Permissions dialog:

1. Click `Add User`
2. In the user textbox, type the username of the user that will be given access
3. Change the `Permission` drop-down to "View", "Edit", or "Admin"
4. Click `Save`

#### Add a Group to a Project
From the Project Permissions dialog:

1. Click the `Groups` tab at the top
2. Click `Add Group`
3. In the group textbox, type the name of the group that will be given access
4. Change the `Permission` drop-down to "View", "Edit", or "Admin"
5. Click `Save`

#### Remove a User from a Project
From the Project Permissions dialog:

1. Click the user you would like to remove
2. Click the `Remove User(s)` button at the bottom left
3. Click `Save`

#### Add a Group to a Project
From the Project Permissions dialog:

1. Click the `Groups` tab at the top
2. Click the group you would like to remove
3. Click the `Remove Group(s) button at the bottom left
4. Click `Save`


## Managing Files
Managing files within a Project, as of Binary Ninja 4.0, is now handled through the Project Browser. More information can now be found in the main Binary Ninja documentation.


## Syncing Changes

### Sync File Changes
1. Open a project file
2. Click the `Sync` button in the bottom left on the window
    1. If there are any conflicts when syncing see, [Resolving Conflicts](#resolving-conflicts) below

### Resolving Conflicts
If there has been a conflict while syncing changes that cannot be resolved automatically, the Resolve Merge Conflict dialog will open.

1. Select a conflict to resolve
2. Inspect the left and right sides of the conflict
3. Click either `Choose Left` or `Choose Right` to select one of the changes, or click `Cancel Merge` if you wish to cancel Syncing and merge later
    1. If there are many conflicts and wish to resolve them all to the same direction, click either `Choose All Left` or `Choose All Right` to select one side for all conflicts

### Named Snapshots
When you sync your changes, you will be prompted to enter a summary of your changes. These summaries can be seen by all members of your Project by opening the file and using `File` > `Collaboration` > `File Changelog`.

You can also annotate specific points in your analysis history without necessarily syncing, by using the `File` > `Collaboration` > `Create Named Snapshot` action. On syncing, these named snapshot summaries will also be uploaded.


## Live Chat

Live chat is provided by the Chat sidebar widget (the icon is two speech bubbles).

### Send Chat Messages
1. Open the chat window
2. Type your message into the text box at the bottom of the chat panel
3. Press "Enter" or "Return" to send your message

### Link to an Address in Chat
1. Open the chat window
2. Type the address in with `0x` at the front (e.g. `0x0000face`)
3. Press "Enter" or "Return" to send your message
