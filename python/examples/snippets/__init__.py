#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import re
import codecs
from PySide2.QtWidgets import (QLineEdit, QPushButton, QApplication, QTextEdit, QWidget,
     QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
     QInputDialog, QMessageBox, QHeaderView, QMenu, QAction, QKeySequenceEdit,
     QPlainTextEdit)
from PySide2.QtCore import (QDir, QObject, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
from PySide2.QtGui import (QFont, QFontMetrics, QDesktopServices, QKeySequence, QIcon)
from binaryninja import user_plugin_path
from binaryninja.plugin import PluginCommand, MainThreadActionHandler
from binaryninja.mainthread import execute_on_main_thread
from binaryninja.log import (log_error, log_debug)
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, DockHandler,
     getThemeColor, ThemeColor)
import numbers
from .QCodeEditor import QCodeEditor, PythonHighlighter

snippetPath = os.path.realpath(os.path.join(user_plugin_path(), "..", "snippets"))
try:
    if not os.path.exists(snippetPath):
        os.mkdir(snippetPath)
except IOError:
    log_error("Unable to create %s" % snippetPath)


def includeWalk(dir, includeExt):
    filePaths = []
    for (root, dirs, files) in os.walk(dir):
        for f in files:
            if os.path.splitext(f)[1] in includeExt:
                filePaths.append(os.path.join(root, f))
    return filePaths


def loadSnippetFromFile(snippetPath):
    try:
        snippetText = codecs.open(snippetPath, 'r', "utf-8").readlines()
    except:
        return ("", "", "")
    if (len(snippetText) < 3):
        return ("", "", "")
    else:
        qKeySequence = QKeySequence(snippetText[1].strip()[1:])
        if qKeySequence.isEmpty():
            qKeySequence = None
        return (snippetText[0].strip()[1:],
                qKeySequence,
                ''.join(snippetText[2:])
        )


def actionFromSnippet(snippetName, snippetDescription):
    if not snippetDescription:
        shortName = os.path.basename(snippetName)
        if shortName.endswith('.py'):
            shortName = shortName[:-3]
        return "Snippets\\" + shortName
    else:
        return "Snippets\\" + snippetDescription


def executeSnippet(code, context):
    snippetGlobals = {}
    if context.binaryView == None:
        dock = DockHandler.getActiveDockHandler()
        if not dock:
            log_error("Snippet triggered with no context and no dock handler. This should not happen. Please report reproduction steps if possible.")
            return
        viewFrame = dock.getViewFrame()
        if not viewFrame:
            log_error("Snippet triggered with no context and no view frame. Snippets require at least one open binary.")
            return
        viewInterface = viewFrame.getCurrentViewInterface()
        context.binaryView = viewInterface.getData()
    snippetGlobals['current_view'] = context.binaryView
    snippetGlobals['bv'] = context.binaryView
    if not context.function:
        if not context.lowLevelILFunction:
            if not context.mediumLevelILFunction:
                snippetGlobals['current_mlil'] = None
                snippetGlobals['current_function'] = None
                snippetGlobals['current_llil'] = None
            else:
                snippetGlobals['current_mlil'] = context.mediumLevelILFunction
                snippetGlobals['current_function'] = context.mediumLevelILFunction.source_function
                snippetGlobals['current_llil'] = context.mediumLevelILFunction.source_function.llil
        else:
            snippetGlobals['current_llil'] = context.lowLevelILFunction
            snippetGlobals['current_function'] = context.lowLevelILFunction.source_function
            snippetGlobals['current_mlil'] = context.lowLevelILFunction.source_function.mlil
    else:
        snippetGlobals['current_function'] = context.function
        snippetGlobals['current_mlil'] = context.function.mlil
        snippetGlobals['current_llil'] = context.function.llil
        snippetGlobals['current_token'] = context.function.llil

    if context.function is not None:
        snippetGlobals['current_basic_block'] = context.function.get_basic_block_at(context.address)
    else:
        snippetGlobals['current_basic_block'] = None
    snippetGlobals['current_address'] = context.address
    snippetGlobals['here'] = context.address
    if context.address is not None and isinstance(context.length, int):
        snippetGlobals['current_selection'] = (context.address, context.address+context.length)
    else:
        snippetGlobals['current_selection'] = None
    snippetGlobals['uicontext'] = context

    exec("from binaryninja import *", snippetGlobals)
    exec(code, snippetGlobals)
    if snippetGlobals['here'] != context.address:
        context.binaryView.file.navigate(context.binaryView.file.view, snippetGlobals['here'])
    if snippetGlobals['current_address'] != context.address:
        context.binaryView.file.navigate(context.binaryView.file.view, snippetGlobals['current_address'])


def makeSnippetFunction(code):
    return lambda context: executeSnippet(code, context)

class Snippets(QDialog):

    def __init__(self, context, parent=None):
        super(Snippets, self).__init__(parent)
        # Create widgets
        self.setWindowModality(Qt.ApplicationModal)
        self.title = QLabel(self.tr("Snippet Editor"))
        self.saveButton = QPushButton(self.tr("&Save"))
        self.saveButton.setShortcut(QKeySequence(self.tr("Ctrl+S")))
        self.runButton = QPushButton(self.tr("&Run"))
        self.runButton.setShortcut(QKeySequence(self.tr("Ctrl+R")))
        self.closeButton = QPushButton(self.tr("Close"))
        self.clearHotkeyButton = QPushButton(self.tr("Clear Hotkey"))
        self.setWindowTitle(self.title.text())
        #self.newFolderButton = QPushButton("New Folder")
        self.browseButton = QPushButton("Browse Snippets")
        self.browseButton.setIcon(QIcon.fromTheme("edit-undo"))
        self.deleteSnippetButton = QPushButton("Delete")
        self.newSnippetButton = QPushButton("New Snippet")
        self.edit = QCodeEditor(HIGHLIGHT_CURRENT_LINE=False, SyntaxHighlighter=PythonHighlighter)
        self.edit.setPlaceholderText("python code")
        self.resetting = False
        self.columns = 3
        self.context = context

        self.keySequenceEdit = QKeySequenceEdit(self)
        self.currentHotkey = QKeySequence()
        self.currentHotkeyLabel = QLabel("")
        self.currentFileLabel = QLabel()
        self.currentFile = ""
        self.snippetDescription = QLineEdit()
        self.snippetDescription.setPlaceholderText("optional description")

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
        #treeButtons.addWidget(self.newFolderButton)
        treeButtons.addWidget(self.browseButton)
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
        buttons.addWidget(self.closeButton)
        buttons.addWidget(self.runButton)
        buttons.addWidget(self.saveButton)

        description = QHBoxLayout()
        description.addWidget(QLabel(self.tr("Description: ")))
        description.addWidget(self.snippetDescription)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addLayout(description)
        vlayout.addWidget(self.edit)
        vlayout.addLayout(buttons)
        vlayoutWidget.setLayout(vlayout)

        hsplitter = QSplitter()
        hsplitter.addWidget(treeWidget)
        hsplitter.addWidget(vlayoutWidget)

        hlayout = QHBoxLayout()
        hlayout.addWidget(hsplitter)

        self.showNormal() #Fixes bug that maximized windows are "stuck"
        #Because you can't trust QT to do the right thing here
        if (sys.platform == "darwin"):
            self.settings = QSettings("Vector35", "Snippet Editor")
        else:
            self.settings = QSettings("Vector 35", "Snippet Editor")
        if self.settings.contains("ui/snippeteditor/geometry"):
            self.restoreGeometry(self.settings.value("ui/snippeteditor/geometry"))
        else:
            self.edit.setMinimumWidth(80 * font.averageCharWidth())
            self.edit.setMinimumHeight(30 * font.lineSpacing())

        # Set dialog layout
        self.setLayout(hlayout)

        # Add signals
        self.saveButton.clicked.connect(self.save)
        self.closeButton.clicked.connect(self.close)
        self.runButton.clicked.connect(self.run)
        self.clearHotkeyButton.clicked.connect(self.clearHotkey)
        self.tree.selectionModel().selectionChanged.connect(self.selectFile)
        self.newSnippetButton.clicked.connect(self.newFileDialog)
        self.deleteSnippetButton.clicked.connect(self.deleteSnippet)
        #self.newFolderButton.clicked.connect(self.newFolder)
        self.browseButton.clicked.connect(self.browseSnippets)

        if self.settings.contains("ui/snippeteditor/selected"):
            selectedName = self.settings.value("ui/snippeteditor/selected")
            self.tree.selectionModel().select(self.files.index(selectedName), QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            if self.tree.selectionModel().hasSelection():
                self.selectFile(self.tree.selectionModel().selection(), None)
                self.edit.setFocus()
                cursor = self.edit.textCursor()
                cursor.setPosition(self.edit.document().characterCount()-1)
                self.edit.setTextCursor(cursor)
            else:
                self.readOnly(True)
        else:
            self.readOnly(True)


    @staticmethod
    def registerAllSnippets():
        for action in list(filter(lambda x: x.startswith("Snippets\\"), UIAction.getAllRegisteredActions())):
            if action == "Snippets\\Snippet Editor...":
                continue
            UIActionHandler.globalActions().unbindAction(action)
            Menu.mainMenu("Tools").removeAction(action)
            UIAction.unregisterAction(action)

        for snippet in includeWalk(snippetPath, ".py"):
            snippetKeys = None
            (snippetDescription, snippetKeys, snippetCode) = loadSnippetFromFile(snippet)
            actionText = actionFromSnippet(snippet, snippetDescription)
            if snippetCode:
                if snippetKeys == None:
                    UIAction.registerAction(actionText)
                else:
                    UIAction.registerAction(actionText, snippetKeys)
                UIActionHandler.globalActions().bindAction(actionText, UIAction(makeSnippetFunction(snippetCode)))
                Menu.mainMenu("Tools").addAction(actionText, "Snippets")

    def clearSelection(self):
        self.keySequenceEdit.clear()
        self.currentHotkey = QKeySequence()
        self.currentHotkeyLabel.setText("")
        self.currentFileLabel.setText("")
        self.snippetDescription.setText("")
        self.edit.clear()
        self.tree.clearSelection()
        self.currentFile = ""

    def reject(self):
        self.settings.setValue("ui/snippeteditor/geometry", self.saveGeometry())

        if self.snippetChanged():
            question = QMessageBox.question(self, self.tr("Discard"), self.tr("You have unsaved changes, quit anyway?"))
            if question != QMessageBox.StandardButton.Yes:
                return
        self.accept()

    def browseSnippets(self):
        url = QUrl.fromLocalFile(snippetPath)
        QDesktopServices.openUrl(url);

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
        if len(new.indexes()) == 0:
            self.clearSelection()
            self.currentFile = ""
            self.readOnly(True)
            return
        newSelection = self.files.filePath(new.indexes()[0])
        self.settings.setValue("ui/snippeteditor/selected", newSelection)
        if QFileInfo(newSelection).isDir():
            self.readOnly(True)
            self.clearSelection()
            self.currentFile = ""
            return

        if old and old.length() > 0:
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
        (snippetDescription, snippetKeys, snippetCode) = loadSnippetFromFile(self.currentFile)
        self.snippetDescription.setText(snippetDescription) if snippetDescription else self.snippetDescription.setText("")
        self.keySequenceEdit.setKeySequence(snippetKeys) if snippetKeys else self.keySequenceEdit.setKeySequence(QKeySequence(""))
        self.edit.setPlainText(snippetCode) if snippetCode else self.edit.setPlainText("")
        self.readOnly(False)

    def newFileDialog(self):
        (snippetName, ok) = QInputDialog.getText(self, self.tr("Snippet Name"), self.tr("Snippet Name: "))
        if ok and snippetName:
            if not snippetName.endswith(".py"):
                snippetName += ".py"
            index = self.tree.selectionModel().currentIndex()
            selection = self.files.filePath(index)
            if QFileInfo(selection).isDir():
                path = os.path.join(selection, snippetName)
            else:
                path = os.path.join(snippetPath, snippetName)
                self.readOnly(False)
            open(path, "w").close()
            self.tree.setCurrentIndex(self.files.index(path))
            log_debug("Snippet %s created." % snippetName)

    def readOnly(self, flag):
        self.keySequenceEdit.setEnabled(not flag)
        self.snippetDescription.setReadOnly(flag)
        self.edit.setReadOnly(flag)
        if flag:
            self.snippetDescription.setDisabled(True)
            self.edit.setDisabled(True)
        else:
            self.snippetDescription.setEnabled(True)
            self.edit.setEnabled(True)

    def deleteSnippet(self):
        selection = self.tree.selectedIndexes()[::self.columns][0] #treeview returns each selected element in the row
        snippetName = self.files.fileName(selection)
        question = QMessageBox.question(self, self.tr("Confirm"), self.tr("Confirm deletion: ") + snippetName)
        if (question == QMessageBox.StandardButton.Yes):
            log_debug("Deleting snippet %s." % snippetName)
            self.clearSelection()
            self.files.remove(selection)
            self.registerAllSnippets()

    def snippetChanged(self):
        if (self.currentFile == "" or QFileInfo(self.currentFile).isDir()):
            return False
        (snippetDescription, snippetKeys, snippetCode) = loadSnippetFromFile(self.currentFile)
        if snippetKeys == None and not self.keySequenceEdit.keySequence().isEmpty():
            return True
        if snippetKeys != None and snippetKeys != self.keySequenceEdit.keySequence().toString():
            return True
        return self.edit.toPlainText() != snippetCode or \
               self.snippetDescription.text() != snippetDescription

    def save(self):
        log_debug("Saving snippet %s" % self.currentFile)
        outputSnippet = codecs.open(self.currentFile, "w", "utf-8")
        outputSnippet.write("#" + self.snippetDescription.text() + "\n")
        outputSnippet.write("#" + self.keySequenceEdit.keySequence().toString() + "\n")
        outputSnippet.write(self.edit.toPlainText())
        outputSnippet.close()
        self.registerAllSnippets()

    def run(self):
        if self.context == None:
            log_warn("Cannot run snippets outside of the UI at this time.")
            return
        if self.snippetChanged():
            question = QMessageBox.question(self, self.tr("Confirm"), self.tr("You have unsaved changes, must save first. Save?"))
            if (question == QMessageBox.StandardButton.No):
                return
            else:
                self.save()
        actionText = actionFromSnippet(self.currentFile, self.snippetDescription.text())
        UIActionHandler.globalActions().executeAction(actionText, self.context)

        log_debug("Saving snippet %s" % self.currentFile)
        outputSnippet = codecs.open(self.currentFile, "w", "utf-8")
        outputSnippet.write("#" + self.snippetDescription.text() + "\n")
        outputSnippet.write("#" + self.keySequenceEdit.keySequence().toString() + "\n")
        outputSnippet.write(self.edit.toPlainText())
        outputSnippet.close()
        self.registerAllSnippets()

    def clearHotkey(self):
        self.keySequenceEdit.clear()


def launchPlugin(context):
    snippets = Snippets(context)
    snippets.exec_()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    snippets = Snippets(None)
    snippets.show()
    sys.exit(app.exec_())
else:
    Snippets.registerAllSnippets()
    UIAction.registerAction("Snippets\\Snippet Editor...")
    UIActionHandler.globalActions().bindAction("Snippets\\Snippet Editor...", UIAction(launchPlugin))
    Menu.mainMenu("Tools").addAction("Snippets\\Snippet Editor...", "Snippet")
