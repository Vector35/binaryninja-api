# Troubleshooting

Occasionally, you may encounter issues with the Enterprise client. Here are some common issues and troubleshooting steps to fix them:


## Cannot Connect to Enterprise Server

If you have multiple copies of Binary Ninja installed, it is often difficult to get the correct client connected when clicking on the Connect button on the Enterprise server's front page. If you are having trouble getting your client connected (or if you have already connected your client, but the server has moved), you will want to edit the `enterprise.server.url` key in your `settings.json` file. This file should be found in your user folder:

* **macOS:** `~/Library/Application Support/Binary Ninja/settings.json`
* **Linux:** `~/.binaryninja/settings.json`
* **Windows:** `%APPDATA%\Binary Ninja\settings.json`

This is also the intended workaround for any other situations where you cannot get the client connected. This setting is currently not able to be changed while the Enterprise client is running and must be changed manually.

!!! warning
    If you are always getting the dialog to connect to the initial server every time you launch the client, make sure your `settings.json` file is valid JSON. An extra trailing comma on the last entry, or a missed trailing slash on an earlier entry, are common culprits.


## Cannot Check Out License

`Enterprise Server failed loading metadata.`

This means that the Enterprise server, after connection, did not provide your client with metadata required to check out a new license. The most common cause of this error is having invalid cached credentials that leave you in a partially logged-in state.

The easiest way to fix this is to close Binary Ninja Enterprise and move or remove the `keychain` folder that is found in your user folder:

* **macOS:** `~/Library/Application Support/Binary Ninja/keychain`
* **Linux:** `~/.binaryninja/keychain`
* **Windows:** `%APPDATA%\Binary Ninja\keychain`


## Cannot Save or Sync Because Database is Locked

Binary Ninja is only able to have a single instance of any given database open at a time. If you open another instance and try to save or sync (which requires saving), you may encounter an error that states the database is locked and cannot be modified. In order to save, you will need to locate the other open copy of the database on your computer and close it. In order to sync, you may need to additionally restart the Enterprise client.

If you have followed these instructions and are still unable to save or sync, please contact support.
