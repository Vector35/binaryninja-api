from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QApplication, QMainWindow
from PySide6.QtCore import Qt, QPoint
import binaryninjaui

class TooltipPopup(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent, Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setWindowTitle("Tooltip Popup")

        layout = QVBoxLayout()
        label = QLabel("This is a tooltip-style popup. Press ESC to close.")
        layout.addWidget(label)

        self.setLayout(layout)
        self.adjustSize()

    def keyPressEvent(self, event):
        # This causes the fake tooltip to be closed when you hit Esc
        if event.key() == Qt.Key_Escape:
            print("Escape key pressed")
            self.close()
            event.accept()
        else:
            super().keyPressEvent(event)

    def showEvent(self, event):
        # This forces the fake tooltip to be focused
        super().showEvent(event)
        self.raise_()
        self.activateWindow()
        self.setFocus()
    
    def focusOutEvent(self, event):
        # This closes the fake tooltip when the user clicks into another UI element
        print("Lost focus")
        self.close()
        super().focusOutEvent(event)

def show_tooltip_popup(parent, pos):
    tooltip_popup = TooltipPopup(parent)
    tooltip_popup.move(pos)
    tooltip_popup.show() 
    parent.tooltip_popup = tooltip_popup  # Keep a reference to the tooltip

# Assuming this is within the context of an existing PySide6 application
ctx = binaryninjaui.UIContext.allContexts()[0]
mw = ctx.mainWindow()

execute_on_main_thread(lambda: show_tooltip_popup(mw, QPoint(100, 100)))
