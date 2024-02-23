# Projects

Projects provide a way to keep and organize related binaries, databases, and resources in a managed format.

???+ Important "Supported Editions"
    Projects are only available in the Commercial and Enterprise editions of Binary Ninja

## Creating a Project

A new project can be created by either selecting `New Project` from the new tab page or `File > New Project` from the application toolbar. After creation, the new project will be opened automatically.


## Opening a Project

Existing projects can be opened by:

- Opening the `.bnpm` (or `.bnpr` on macOS) like any other file in Binary Ninja
- Double-clicking the project from the "Recent Projects" list in a new tab

When a project is first opened, a new window will be created for it. This window is permanently tied to this project, meaning that it will only contain files associated with this project.


## Structure on Disk

A project has a few components stored on disk:

- A top-level `.bnpr` directory that contains everything
- A `project.bnpm` project metadata file
- Optionally a `settings.json` file if project settings have been modified
- A `data` directory that contains the data for files in the project


## Project Browser

The primary method of interaction with a project is through the "Project Browser" UI

<!-- TODO: FINISH IMAGE, ORIGINAL IN CHAT -->

1. The name of the project
2. Edit project details
3. Description of project
4. Import files to the project
5. Import a folder to the project
6. View and modify project-level settings
7. Tab for project file tree
8. Tab for Recent project file list
9. Refresh project
10. Filter the current view for files and folders
11. Project contents tree
12. Info widget showing details about the currently selected items
13. Description of currently selected item


### Adding Files to a Project

There are a handful of ways to add files to a project:

- Drag and drop files and folders directly into the project browser
- Using the `Import Files` button, select files to add to the currently selected folder
- Using the `Import Folder` button, select a folder to recursively import under the selected folder


### Exporting Files from a Project

To export files/folders from a project, select any number of files and folders in the project browser and choose `Export Selected` from the context menu or `Project Browser - Export Selected` from the command palette.


### Batch Analysis

Files in a project can be batch-analyzed easily from the project browser. Simply select the files to analyze and choose `Analyze Selected` from the context menu or `Project Browser - Analyze Selected` from the command palette. This will create a BNDB for each selected file, unless it is a BNDB itself.


## Project Settings

Project level settings let you set project-wide settings that apply to every file in the project. See the [settings documentation](settings.md) for more information.


## External Links

- Able to link symbols to external destinations in libraries


### screenshot of external links widget here


### External Libraries

An External Library represents a full library, optionally backed by a project file (e.g. `libc.so` which is backed by `libc.bndb`)

<!-- TODO: Screenshot of editing external library -->

### External Locations

An External Location represents a symbol that points to an external target address and/or symbol in an External Library (e.g. `strcpy` points to `0x1234` in `libc.so`)

<!-- TODO: Screenshot of editing external location here -->

Note that external locations can be mass-selected and dragged to a library
