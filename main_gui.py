#!/usr/bin/env python3
"""
Графический интерфейс для пакетного анализа IDA.
"""
import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    # В Qt6 high-DPI масштабирование работает автоматически, дополнительные настройки не нужны.
    window = MainWindow()
    print("test")
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()