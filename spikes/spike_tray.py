"""Spike 1: does a PySide6 tray icon work on this Hyprland setup?

Run:  python spikes/spike_tray.py
Look for the icon in your bar's tray, right-click it, try both menu items.
"""
import sys

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)  # keep running with no window, like Courier will

print("Qt platform:", app.platformName())  # expect "wayland"
print("Tray available:", QSystemTrayIcon.isSystemTrayAvailable())

icon = app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
tray = QSystemTrayIcon(icon)
tray.setToolTip("Clipboard Courier spike")

menu = QMenu()
hello = QAction("Show notification")
hello.triggered.connect(lambda: tray.showMessage("Courier", "Tray menu works"))
quit_action = QAction("Quit")
quit_action.triggered.connect(app.quit)
menu.addAction(hello)
menu.addAction(quit_action)

tray.setContextMenu(menu)
tray.activated.connect(lambda reason: print("Tray activated:", reason))
tray.show()

sys.exit(app.exec())
