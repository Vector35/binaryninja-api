# Triage
Author: **Vector 35**

## Description
The triage plugin is meant to serve as an example of the new Binary Ninja UI plugin capability and also to demonstrate how you can adapt the core analysis capabilities to different workflows.

In particular, the Triage plugin:

* Adds a new button to the new page dialog
* Creates a file choosing UI to quickly select a large number of files for triage
* Adds two new views, a triage view with high level summary information, and a Byte Overview which shows the contents of files in a high-density form
* New for [SAS](https://twitter.com/TheSAScon/status/1110691127215030272), the plugin enables finding cross-references to dynamically loaded functions.

## Installation

This plugin is included by default if you are running the appropriate version of Binary Ninja (you may need to switch to the development channel in your [preferences](http://docs.binary.ninja/getting-started.html#preferencesupdates). To enable, simply copy from your [install path](http://docs.binary.ninja/getting-started.html#binary-path) to your [user](http://docs.binary.ninja/getting-started.html#user-folder)/plugins folder. 

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - N/A
 * dev - 1560 or newer

## License

This plugin is released under a [MIT](LICENSE) license.
