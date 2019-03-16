#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import re
from PySide2.QtWidgets import (QLineEdit, QPushButton, QApplication, QTextEdit, QWidget,
    QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter, 
    QInputDialog, QMessageBox, QHeaderView, QMenu, QAction, QKeySequenceEdit,
    QPlainTextEdit)
from PySide2.QtCore import (QDir, QObject, Qt, QFileInfo, QItemSelectionModel, QSettings)
from PySide2.QtGui import (QFont, QFontMetrics, QDesktopServices, QKeySequence)
from binaryninja import user_plugin_path
from binaryninja.plugin import PluginCommand, MainThreadActionHandler
from binaryninja.mainthread import execute_on_main_thread
from binaryninja.log import (log_info, log_warn, log_alert, log_debug)
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler)

snippetPath = os.path.realpath(os.path.join(user_plugin_path(), "..", "snippets"))

def includeWalk(dir, includeExt):
    filePaths = []
    for (root, dirs, files) in os.walk(dir):
        for f in files:
            if os.path.splitext(f)[1] in includeExt:
                filePaths.append(os.path.join(root, f))
    return filePaths

def loadSnippetFromFile(snippetPath):
    try:
        snippetText = open(snippetPath, 'r').readlines()
    except:
        return (False, [], False)
    if (len(snippetText) < 3):
        return (False, [], False)
    else:
        qKeySequence = QKeySequence(snippetText[1].strip()[1:])
        if qKeySequence.isEmpty():
            qKeySequence = []
        else:
            qKeySequence = [qKeySequence]
        return (snippetText[0].strip()[1:], 
                qKeySequence,
                ''.join(snippetText[2:])
        )

class Snippets(QDialog):

    def __init__(self, parent=None):
        super(Snippets, self).__init__(parent)
        # Create widgets
        self.setWindowModality(Qt.NonModal)
        self.title = QLabel(self.tr("Snippet Editor"))
        self.saveButton = QPushButton(self.tr("Save"))
        self.revertButton = QPushButton(self.tr("Revert"))
        self.clearHotkeyButton = QPushButton(self.tr("Clear Hotkey"))
        self.setWindowTitle(self.title.text())
        self.newFolderButton = QPushButton("New Folder")
        self.deleteSnippetButton = QPushButton("Delete")
        self.newSnippetButton = QPushButton("New Snippet")
        self.edit = QPlainTextEdit()
        self.resetting = False
        self.columns = 3

        self.keySequenceEdit = QKeySequenceEdit(self)
        self.currentHotkey = QKeySequence()
        self.currentHotkeyLabel = QLabel("")
        self.currentFileLabel = QLabel()
        self.currentFile = ""
        self.snippetDescription = QLineEdit()
        self.snippetEditsPending = False

        self.clearSelection()

        #Set Editbox Size
        font = getMonospaceFont(self)
        self.edit.setFont(font)
        font = QFontMetrics(font)
        self.edit.setTabStopWidth(4 * font.width(' ')); #TODO, replace with settings API

        #Files
        self.files = QFileSystemModel()
        self.files.setRootPath(snippetPath)
        self.files.setNameFilters(["*.py"])

        #Tree
        self.tree = QTreeView()
        self.tree.setModel(self.files)
        self.tree.setSortingEnabled(True)
        self.tree.hideColumn(2)
        self.tree.sortByColumn(0, Qt.AscendingOrder)
        self.tree.setRootIndex(self.files.index(snippetPath))
        for x in range(self.columns):
            #self.tree.resizeColumnToContents(x)
            self.tree.header().setSectionResizeMode(x, QHeaderView.ResizeToContents) 
        treeLayout = QVBoxLayout()
        treeLayout.addWidget(self.tree)
        treeButtons = QHBoxLayout()
        treeButtons.addWidget(self.newFolderButton)
        treeButtons.addWidget(self.newSnippetButton)
        treeButtons.addWidget(self.deleteSnippetButton)
        treeLayout.addLayout(treeButtons)
        treeWidget = QWidget()
        treeWidget.setLayout(treeLayout)

        # Create layout and add widgets
        buttons = QHBoxLayout()
        buttons.addWidget(self.clearHotkeyButton)
        buttons.addWidget(self.keySequenceEdit)
        buttons.addWidget(self.currentHotkeyLabel)
        buttons.addWidget(self.revertButton)
        buttons.addWidget(self.saveButton)

        description = QHBoxLayout()
        description.addWidget(QLabel(self.tr("Description: ")))
        description.addWidget(self.snippetDescription)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addWidget(self.currentFileLabel)
        vlayout.addWidget(self.edit)
        vlayout.addLayout(description)
        vlayout.addLayout(buttons)
        vlayoutWidget.setLayout(vlayout)

        hsplitter = QSplitter()
        hsplitter.addWidget(treeWidget)
        hsplitter.addWidget(vlayoutWidget)

        hlayout = QHBoxLayout()
        hlayout.addWidget(hsplitter)

        self.showNormal() #Fixes bug that maximized windows are "stuck"
        self.settings = QSettings("Vector35", "Snippet Editor")
        if self.settings.contains("ui/snippeteditor/geometry"):
            self.restoreGeometry(self.settings.value("ui/snippeteditor/geometry"))
        else:
            self.edit.setMinimumWidth(80 * font.averageCharWidth())
            self.edit.setMinimumHeight(30 * font.lineSpacing())

        # Set dialog layout
        self.setLayout(hlayout)

        # Add signals
        self.saveButton.clicked.connect(self.save)
        self.revertButton.clicked.connect(self.loadSnippet)
        self.clearHotkeyButton.clicked.connect(self.clearHotkey)
        self.tree.selectionModel().selectionChanged.connect(self.selectFile)
        self.newSnippetButton.clicked.connect(self.newFileDialog)
        self.deleteSnippetButton.clicked.connect(self.deleteSnippet)
        self.newFolderButton.clicked.connect(self.newFolder)

    def executeSnippet(self, code, context):
        snippetGlobals = {}
        snippetGlobals['current_view'] = context.binaryView
        snippetGlobals['bv'] = context.binaryView
        snippetGlobals['current_function'] = context.function
        #snippetGlobals['current_basic_block'] = context.block
        snippetGlobals['current_address'] = context.address
        snippetGlobals['here'] = context.address
        snippetGlobals['current_selection'] = (context.address, context.address+context.length)
        snippetGlobals['current_llil'] = context.lowLevelILFunction
        snippetGlobals['current_mlil'] = context.mediumLevelILFunction

        exec("from binaryninja import *", snippetGlobals)
        exec(code, snippetGlobals)
        if snippetGlobals['here'] != context.address:
            context.binaryView.file.navigate(context.binaryView.file.view, snippetGlobals['here'])
        if snippetGlobals['current_address'] != context.address:
            context.binaryView.file.navigate(context.binaryView.file.view, snippetGlobals['current_address'])

    def makeSnippetFunction(self, code):
        return lambda context: self.executeSnippet(code, context)

    def registerAllSnippets(self):
        for action in list(filter(lambda x: x.startswith("Snippet\\"), UIAction.getAllRegisteredActions())):
            UIAction.registerAction(action, [])

        for snippet in includeWalk(snippetPath, ".py"):
            (snippetDescription, snippetKey, snippetCode) = loadSnippetFromFile(snippet)
            if not snippetDescription:
                actionText = "Snippet\\" + snippet
            else:
                actionText = "Snippet\\" + snippetDescription
            UIAction.registerAction(actionText, snippetKey)
            UIActionHandler.globalActions().bindAction(actionText, UIAction(self.makeSnippetFunction(snippetCode)))

    def clearSelection(self):
        self.keySequenceEdit.clear()
        self.currentHotkey = QKeySequence()
        self.currentHotkeyLabel.setText("")
        self.currentFileLabel.setText("")
        self.snippetDescription.setText("")
        self.edit.setPlainText("")

    def reject(self):
        self.settings.setValue("ui/snippeteditor/geometry", self.saveGeometry())

        if self.snippetChanged():
            question = QMessageBox.question(self, self.tr("Discard"), self.tr("You have unsaved changes, quit anyway?"))
            if question != QMessageBox.StandardButton.Yes:
                return
        self.accept()

    def newFolder(self):
        (folderName, ok) = QInputDialog.getText(self, self.tr("Folder Name"), self.tr("Folder Name: "))
        if ok and folderName:
            index = self.tree.selectionModel().currentIndex()
            selection = self.files.filePath(index)
            if QFileInfo(selection).isDir():
                QDir(selection).mkdir(folderName)
            else:
                QDir(snippetPath).mkdir(folderName)    

    def selectFile(self, new, old):
        if (self.resetting):
            self.resetting = False
            return
        newSelection = self.files.filePath(new.indexes()[0])
        if QFileInfo(newSelection).isDir():
            self.clearSelection()
            return

        if old.length() > 0:
            oldSelection = self.files.filePath(old.indexes()[0])
            if not QFileInfo(oldSelection).isDir() and self.snippetChanged():
                question = QMessageBox.question(self, self.tr("Discard"), self.tr("Snippet changed. Discard changes?"))
                if question != QMessageBox.StandardButton.Yes:
                    self.resetting = True
                    self.tree.selectionModel().select(old, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
                    return False

        self.currentFile = newSelection
        self.loadSnippet()

    def loadSnippet(self):
        self.currentFileLabel.setText(QFileInfo(self.currentFile).baseName())
        log_debug("Loading %s as a snippet." % self.currentFile)
        (snippetDescription, snippetKey, snippetCode) = loadSnippetFromFile(self.currentFile)
        self.snippetDescription.setText(snippetDescription) if snippetDescription else self.snippetDescription.setText("")
        self.keySequenceEdit.setKeySequence(snippetKey[0]) if len(snippetKey) != 0 else self.keySequenceEdit.setKeySequence(QKeySequence(""))
        self.edit.setPlainText(snippetCode) if snippetCode else self.edit.setPlainText("")

    def newFileDialog(self):
        (snippetName, ok) = QInputDialog.getText(self, self.tr("Snippet Name"), self.tr("Snippet Name: "))
        if ok and snippetName:
            if not snippetName.endswith(".py"):
                snippetName += ".py"
            index = self.tree.selectionModel().currentIndex()
            selection = self.files.filePath(index)
            if QFileInfo(selection).isDir():
                open(os.path.join(selection, snippetName), "w").close()
            else:
                open(os.path.join(snippetPath, snippetName), "w").close()
            log_debug("Snippet %s created." % snippetName)

    def deleteSnippet(self):
        selection = self.tree.selectedIndexes()[::self.columns][0] #treeview returns each selected element in the row
        snippetName = self.files.fileName(selection)
        question = QMessageBox.question(self, self.tr("Confirm"), self.tr("Confirm deletion: ") + snippetName)
        if (question == QMessageBox.StandardButton.Yes):
            log_debug("Deleting snippet %s." % snippetName)
            self.clearSelection()
            self.files.remove(selection)

    def snippetChanged(self):
        if (self.currentFile == "" or QFileInfo(self.currentFile).isDir()):
            return False
        (snippetDescription, snippetKey, snippetCode) = loadSnippetFromFile(self.currentFile)
        if (not snippetCode):
            return False
        if len(snippetKey) == 0 and not self.keySequenceEdit.keySequence().isEmpty():
            return True
        if len(snippetKey) != 0 and snippetKey[0] != self.keySequenceEdit.keySequence():
            return True
        return self.edit.toPlainText() != snippetCode or \
               self.snippetDescription.text() != snippetDescription

    def save(self):
        log_debug("Saving snippet %s" % self.currentFile)
        outputSnippet = open(self.currentFile, "w")
        outputSnippet.write("#" + self.snippetDescription.text() + "\n")
        outputSnippet.write("#" + self.keySequenceEdit.keySequence().toString() + "\n")
        outputSnippet.write(self.edit.toPlainText())
        outputSnippet.close()
        self.registerAllSnippets()

    def clearHotkey(self):
        self.keySequenceEdit.clear()

def launchPlugin(bv):
    snippets = Snippets()
    snippets.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    snippets = Snippets()
    snippets.show()
    sys.exit(app.exec_())
else:
    PluginCommand.register("Snippet Editor", "Sample UI Plugin for small code snippets to be able to executed on a hotkey.", launchPlugin)
    #MainThreadActionHandler.register()
