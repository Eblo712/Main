"""Главное окно приложения с боковым меню и стеком страниц."""
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QSizePolicy,
    QPushButton, QLabel, QProgressBar, QTextEdit, QGroupBox,
    QFileDialog, QStackedWidget, QMessageBox, QApplication, QLineEdit,
    QFormLayout, QSlider, QRadioButton, QButtonGroup, QGridLayout,
    QCheckBox, QFrame, QWhatsThis, QStyle, QProgressDialog
)
from PySide6.QtCore import Qt, QPoint, QThread, Signal, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QFont
from pathlib import Path
from typing import List, Optional
import os
import json
import shutil
import time
import squarify

from ui.worker_threads import AnalysisWorker
from ui.settings_dialog import SettingsPage
from core.config import load_config, get_ida_executable, get_default_inputdir, get_max_ida
from core.discover import find_executables
from core.report_generator import ReportGenerator
from core.ida import IDAAnalyzer
from ui.theme import apply_theme

PLATFORM_EXTENSIONS = {
    "Windows": {"label": "Windows", "exts": [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi"]},
    "Linux / Android": {"label": "Linux / Android", "exts": [".elf", ".so", ".o", ".ko", ".dex"]},
    "macOS / iOS": {"label": "macOS / iOS", "exts": [".mach-o", ".dylib", ".bundle", ".app"]},
    "All platforms": {"label": "Все платформы", "exts": [".exe", ".dll", ".sys", ".elf", ".so", ".o", ".mach-o", ".dylib", ".dex"]},
}

SCRIPT_DIR = Path(__file__).resolve().parent.parent

class ExportWorker(QThread):
    progress_updated = Signal(str, int, int)
    finished = Signal(int, int)
    error_occurred = Signal(str)

    def __init__(self, idb_files: List[Path], script_path: Path,
                 idat_path: str, max_workers: int, parent=None):
        super().__init__(parent)
        self.idb_files = idb_files
        self.script_path = script_path
        self.idat_path = idat_path
        self.max_workers = max_workers
        self.results = {}
        self._cancel = False

    def run(self):
        analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
        analyzer.set_progress_callback(self._on_progress)
        try:
            self.results = analyzer.run_script_on_batch(self.idb_files, self.script_path)
            succeeded = sum(1 for v in self.results.values() if v)
            self.finished.emit(succeeded, len(self.results))
        except Exception as e:
            self.error_occurred.emit(str(e))
            self.finished.emit(0, len(self.idb_files))

    def _on_progress(self, filename: str, current: int, total: int):
        if not self._cancel:
            self.progress_updated.emit(filename, current, total)

    def cancel(self):
        self._cancel = True


class IndexWorker(QThread):
    finished = Signal(bool)
    error_occurred = Signal(str)

    def __init__(self, generator: ReportGenerator, reports_dir: Path,
                 input_dir: Path, report_links: List[dict],
                 sorted_modules: List[str], ida_info: Optional[dict],
                 elf_sections: List[str] = None, parent=None):
        super().__init__(parent)
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.report_links = report_links
        self.sorted_modules = sorted_modules
        self.ida_info = ida_info
        self.elf_sections = elf_sections or []

    def run(self):
        try:
            self.generator.generate_index(
                self.reports_dir,
                self.input_dir,
                self.report_links,
                self.sorted_modules,
                self.ida_info,
                self.elf_sections
            )
            self.finished.emit(True)
        except Exception as e:
            self.error_occurred.emit(str(e))
            self.finished.emit(False)


class TreemapWidget(QWidget):
    """Виджет для отображения treemap файлов."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_items = []          # список словарей: name, size, status, path
        self.rects = []
        self.hovered_index = -1
        self._data_pending = False
        self.setMouseTracking(True)
        self.setMinimumHeight(120)

    def set_data(self, items):
        self.file_items = items
        if self.width() > 0 and self.height() > 0:
            self._compute_layout()
        else:
            self._data_pending = True
        self.update()

    def update_status(self, file_path: str, status: str):
        for item in self.file_items:
            if item['path'] == file_path:
                item['status'] = status
                break
        self.update()

    def showEvent(self, event):
        super().showEvent(event)
        if self._data_pending:
            self._compute_layout()
            self._data_pending = False

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.file_items:
            self._compute_layout()
            self.update()

    def _compute_layout(self):
        if not self.file_items:
            self.rects = []
            return
        sizes = [max(item['size'], 1) for item in self.file_items]
        w, h = self.width(), self.height()
        if w <= 0 or h <= 0:
            self.rects = []
            return
        norm = squarify.normalize_sizes(sizes, w, h)
        coords = squarify.squarify(norm, 0, 0, w, h)
        # squarify возвращает список словарей {'x': ..., 'y': ..., 'dx': ..., 'dy': ...}
        self.rects = [QRectF(d['x'], d['y'], d['dx'], d['dy']) for d in coords]

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        if not self.file_items or not self.rects:
            painter.drawText(self.rect(), Qt.AlignCenter, "Нет данных для отображения")
            return
        for i, rect in enumerate(self.rects):
            if i >= len(self.file_items):
                break
            item = self.file_items[i]
            color = self._color_for_status(item.get('status', 'not_analyzed'))
            painter.fillRect(rect, color)
            painter.setPen(QPen(Qt.black, 1))
            painter.drawRect(rect)
            painter.setFont(QFont("Segoe UI", 7))
            painter.drawText(rect.adjusted(2, 2, -2, -2), Qt.AlignCenter | Qt.TextWordWrap, item['name'][:20])
        if 0 <= self.hovered_index < len(self.rects) and self.hovered_index < len(self.file_items):
            painter.setPen(QPen(Qt.white, 2))
            painter.drawRect(self.rects[self.hovered_index])

    def _color_for_status(self, status):
        colors = {
            'not_analyzed': QColor(192, 192, 192),
            'in_progress': QColor(255, 255, 0),
            'success': QColor(0, 200, 0),
            'error': QColor(255, 0, 0)
        }
        return colors.get(status, QColor(128, 128, 128))

    def mouseMoveEvent(self, event):
        pos = event.position()
        new_index = -1
        for i, rect in enumerate(self.rects):
            if rect.contains(pos):
                new_index = i
                break
        if new_index != self.hovered_index:
            self.hovered_index = new_index
            self.update()
            if new_index >= 0 and new_index < len(self.file_items):
                item = self.file_items[new_index]
                tip = f"{item['name']}\nРазмер: {item['size']} байт\nСтатус: {item.get('status', 'неизвестно')}"
            else:
                tip = ""
            self.setToolTip(tip)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDA Batch Tool")
        self.resize(1100, 750)
        self.cfg = load_config()
        self.current_theme = self.cfg.get("theme", "light")
        self.analysis_in_progress = False
        self.export_in_progress = False
        self.html_in_progress = False
        self.worker = None
        self.export_worker = None
        self.index_worker = None
        self.active_page = 0
        self._cached_files: List[Path] = []

        self._export_results = {}
        self._export_succeeded = 0
        self._export_total = 0

        self._build_ui()
        self._connect_signals()
        apply_theme(QApplication.instance(), self.current_theme)
        self.btn_analysis.setChecked(True)
        self.btn_settings.setChecked(False)
        self._update_menu_styles()
        self._refresh_file_list()

    def _update_menu_styles(self):
        self.btn_analysis.setStyleSheet(self._menu_button_style(self.btn_analysis.isChecked(), self.current_theme))
        self.btn_settings.setStyleSheet(self._menu_button_style(self.btn_settings.isChecked(), self.current_theme))

    @staticmethod
    def _create_help_button(tooltip_text: str) -> QPushButton:
        btn = QPushButton()
        btn.setIcon(btn.style().standardIcon(QStyle.SP_MessageBoxQuestion))
        btn.setFixedSize(20, 20)
        btn.setFlat(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setToolTip("Нажмите для пояснения")
        btn.clicked.connect(
            lambda checked, b=btn, t=tooltip_text: QWhatsThis.showText(
                b.mapToGlobal(QPoint(0, b.height())), t
            )
        )
        return btn

    @staticmethod
    def _menu_button_style(active: bool, theme: str = "light") -> str:
        base = """
            QPushButton {
                text-align: left;
                padding: 8px 12px;
                border-radius: 8px;
                font-weight: 500;
                border: none;
            }
        """
        if active:
            if theme == "dark":
                base += "background-color: #3a3a3c; color: #ffffff;"
            else:
                base += "background-color: #e8e8ed; color: #000;"
        else:
            if theme == "dark":
                base += "background-color: transparent; color: #cccccc;"
                base += " hover { background-color: #3a3a3c; }"
            else:
                base += "background-color: transparent; color: #505050;"
                base += " hover { background-color: #f0f0f5; }"
        return base

    def _create_slider_with_label(self, initial_value, range_min=1, range_max=32):
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        slider = QSlider(Qt.Horizontal)
        slider.setRange(range_min, range_max)
        slider.setValue(initial_value)
        value_label = QLabel(str(initial_value))
        value_label.setFixedWidth(40)
        value_label.setAlignment(Qt.AlignCenter)
        slider.valueChanged.connect(lambda v: value_label.setText(str(v)))
        layout.addWidget(slider)
        layout.addWidget(value_label)
        return container, slider, value_label

    def _build_ui(self):
        central = QWidget(objectName="central")
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Боковая панель
        sidebar = QWidget(objectName="sidebar")
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        sidebar_layout.setSpacing(6)

        title_label = QLabel("IDA Batch")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; margin-bottom: 15px;")
        sidebar_layout.addWidget(title_label)

        self.btn_analysis = QPushButton("  Анализ")
        self.btn_analysis.setCheckable(True)
        self.btn_analysis.setChecked(True)
        self.btn_analysis.setStyleSheet(self._menu_button_style(True, self.current_theme))
        sidebar_layout.addWidget(self.btn_analysis)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sidebar_layout.addWidget(spacer)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        sidebar_layout.addWidget(line)

        self.btn_settings = QPushButton("  Конфигурация")
        self.btn_settings.setCheckable(True)
        self.btn_settings.setChecked(False)
        self.btn_settings.setStyleSheet(self._menu_button_style(False, self.current_theme))
        sidebar_layout.addWidget(self.btn_settings)

        self.pages = QStackedWidget()
        self.analysis_page = self._create_analysis_page()
        self.settings_page = SettingsPage()
        self.settings_page.config_changed.connect(self._on_config_changed)
        self.pages.addWidget(self.analysis_page)
        self.pages.addWidget(self.settings_page)

        self.pages.setCurrentIndex(0)
        self.active_page = 0

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.pages, 1)

    def _create_analysis_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # --- Источник файлов (на всю ширину) ---
        source_group = QGroupBox("Источник файлов")
        source_layout = QVBoxLayout(source_group)
        dir_row = QHBoxLayout()
        self.inputdir_edit = QLineEdit()
        self.inputdir_edit.setPlaceholderText("Путь к папке с бинарными файлами...")
        self.inputdir_edit.setText(get_default_inputdir())
        self.browse_dir_btn = QPushButton("Обзор...")
        dir_row.addWidget(self.inputdir_edit, 1)
        dir_row.addWidget(
            self._create_help_button("Папка, в которой находятся исполняемые файлы для анализа.")
        )
        dir_row.addWidget(self.browse_dir_btn)
        source_layout.addLayout(dir_row)
        layout.addWidget(source_group)

        # --- Две колонки под источником (одинаковой ширины) ---
        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(20)

        # Левая колонка
        left_column = QVBoxLayout()
        left_column.setSpacing(10)
        left_column.setContentsMargins(0, 0, 0, 0)

        scan_group = QGroupBox("Параметры сканирования")
        scan_layout = QVBoxLayout(scan_group)

        platform_group = QGroupBox("Целевая платформа")
        platform_layout = QVBoxLayout(platform_group)

        self.platform_buttons = QButtonGroup(self)
        self.platform_buttons.setExclusive(True)
        self.radio_to_platform = {}
        grid = QGridLayout()
        row, col = 0, 0
        for key, info in PLATFORM_EXTENSIONS.items():
            radio = QRadioButton(info["label"])
            self.platform_buttons.addButton(radio)
            self.radio_to_platform[radio] = key
            ext_list = ", ".join(info["exts"])
            help_btn = self._create_help_button(
                f"Платформа: {info['label']}\nАнализируемые расширения: {ext_list}"
            )
            item_layout = QHBoxLayout()
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.addWidget(radio)
            item_layout.addWidget(help_btn)
            item_layout.addStretch()
            grid.addLayout(item_layout, row, col)
            col += 1
            if col == 2:
                col = 0
                row += 1
        for radio, plat_key in self.radio_to_platform.items():
            if plat_key == "All platforms":
                radio.setChecked(True)
                break
        platform_layout.addLayout(grid)
        scan_layout.addWidget(platform_group)

        self.max_ida_slider_container, self.max_ida_slider, self.max_ida_label = \
            self._create_slider_with_label(min(get_max_ida(), 32), range_max=32)
        slider_row = QHBoxLayout()
        slider_row.addWidget(QLabel("Потоков IDA:"))
        slider_row.addWidget(self.max_ida_slider_container)
        slider_row.addWidget(self._create_help_button(
            "Максимальное количество одновременно работающих экземпляров IDA.\n"
            "Больше потоков – быстрее анализ, но выше нагрузка на процессор."
        ))
        scan_layout.addLayout(slider_row)

        flags_group = QGroupBox("Флаги анализа")
        flags_layout = QVBoxLayout(flags_group)
        self.cleanup_check = QCheckBox("Удалять .asm и .log после успешного анализа")
        self.temp_cleanup_check = QCheckBox("Удалять временные файлы IDA (.id0, .id1, .nam, .til)")
        self.verbose_check = QCheckBox("Подробный лог (--verbose)")
        flags_layout.addWidget(self.cleanup_check)
        flags_layout.addWidget(self.temp_cleanup_check)
        flags_layout.addWidget(self.verbose_check)
        scan_layout.addWidget(flags_group)

        # Кнопки запуска/отмены
        buttons_layout = QHBoxLayout()
        self.start_btn = QPushButton("Запустить анализ")
        self.start_btn.setFixedHeight(40)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setEnabled(False)
        buttons_layout.addWidget(self.start_btn)
        buttons_layout.addWidget(self.cancel_btn)
        scan_layout.addLayout(buttons_layout)

        # Обработка результатов IDA
        json_group = QGroupBox("Обработка результатов IDA")
        json_layout = QVBoxLayout(json_group)

        self.json_export_label = QLabel("Готов к экспорту JSON")
        self.json_progress_bar = QProgressBar()
        self.json_progress_bar.setRange(0, 100)

        self.json_export_btn = QPushButton("IDAtoJSON")
        self.json_export_btn.setEnabled(False)
        self.json_export_btn.setToolTip("Запустить экспорт данных из .i64 в JSON.")

        json_layout.addWidget(self.json_export_label)
        json_layout.addWidget(self.json_progress_bar)
        json_layout.addWidget(self.json_export_btn, alignment=Qt.AlignLeft)

        left_column.addWidget(scan_group)
        left_column.addWidget(json_group)
        left_column.addStretch()

        # --- Правая колонка (переработана) ---
        right_column = QVBoxLayout()
        right_column.setSpacing(10)
        right_column.setContentsMargins(0, 0, 0, 0)

        # Прогресс анализа (компактный)
        self.current_file_label = QLabel("Готов к запуску")
        self.files_found_label = QLabel("")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        right_column.addWidget(self.current_file_label)
        right_column.addWidget(self.files_found_label)
        right_column.addWidget(self.progress_bar)

        # Treemap
        self.treemap = TreemapWidget()
        self.treemap.setMinimumHeight(150)
        right_column.addWidget(self.treemap, 1)  # растягивается

        # Поле ошибок
        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(120)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        right_column.addWidget(self.error_text)

        columns_layout.addLayout(left_column, 1)
        columns_layout.addLayout(right_column, 1)
        layout.addLayout(columns_layout)

        # --- HTML-отчёт (на всю ширину) ---
        html_group = QGroupBox("HTML-отчёт")
        html_layout = QVBoxLayout(html_group)

        self.html_progress_label = QLabel("Готов к созданию HTML")
        self.html_progress_bar = QProgressBar()
        self.html_progress_bar.setRange(0, 100)

        self.html_spinner = QProgressBar()
        self.html_spinner.setRange(0, 0)
        self.html_spinner.setVisible(False)

        self.delete_json_check = QCheckBox("Удалить JSON-файлы после создания отчётов")
        self.delete_json_check.setToolTip("После успешной генерации HTML-отчётов и сводного индекса, JSON-файлы экспорта будут удалены.")
        self.delete_json_check.setChecked(True)

        self.pseudocode_check = QCheckBox("Включить псевдокод в отчёт")
        self.pseudocode_check.setToolTip("Если включено, для каждой функции будет добавлен псевдокод. Это замедляет экспорт.")
        self.pseudocode_check.setChecked(False)

        self.html_generate_btn = QPushButton("Сгенерировать HTML-отчёты")
        self.html_generate_btn.setEnabled(False)
        self.html_generate_btn.setToolTip("Создать интерактивные HTML-отчёты на основе JSON-файлов.")

        html_layout.addWidget(self.html_progress_label)
        html_layout.addWidget(self.html_progress_bar)
        html_layout.addWidget(self.html_spinner)
        html_layout.addWidget(self.delete_json_check)
        html_layout.addWidget(self.pseudocode_check)
        html_layout.addWidget(self.html_generate_btn, alignment=Qt.AlignLeft)
        layout.addWidget(html_group)

        layout.addStretch()
        return page

    def _connect_signals(self):
        self.btn_analysis.clicked.connect(lambda: self.switch_page(0))
        self.btn_settings.clicked.connect(lambda: self.switch_page(1))
        self.browse_dir_btn.clicked.connect(self._browse_input_dir)
        self.start_btn.clicked.connect(self._start_analysis)
        self.cancel_btn.clicked.connect(self._cancel_analysis)
        self.json_export_btn.clicked.connect(self._start_json_export)
        self.html_generate_btn.clicked.connect(self._start_html_generation)

    def switch_page(self, index: int):
        if self.analysis_in_progress and index != 0:
            return
        self.active_page = index
        self.btn_analysis.setChecked(index == 0)
        self.btn_settings.setChecked(index == 1)
        self._update_menu_styles()
        self.pages.setCurrentIndex(index)

    def _browse_input_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для анализа")
        if path:
            self.inputdir_edit.setText(path)
            self._refresh_file_list()

    def _selected_extensions(self):
        checked = self.platform_buttons.checkedButton()
        if checked and checked in self.radio_to_platform:
            return PLATFORM_EXTENSIONS[self.radio_to_platform[checked]]["exts"]
        return PLATFORM_EXTENSIONS["All platforms"]["exts"]

    # ------------------------------------------------------------------
    # Проверка существующих .i64 и управление состоянием
    # ------------------------------------------------------------------
    def _refresh_file_list(self):
        input_dir = self.inputdir_edit.text().strip()
        if not input_dir or not os.path.isdir(input_dir):
            self._cached_files = []
            self.files_found_label.setText("")
            self.json_export_btn.setEnabled(False)
            self.html_generate_btn.setEnabled(False)
            self.treemap.set_data([])
            return

        extensions = self._selected_extensions()
        files = find_executables(input_dir, extensions=extensions)
        self._cached_files = files
        if not files:
            self.files_found_label.setText("Не найдено подходящих файлов.")
            self.json_export_btn.setEnabled(False)
            self.html_generate_btn.setEnabled(False)
            self.treemap.set_data([])
            return

        existing_all = self._all_idbs_exist(files)
        count = len(files)
        if existing_all:
            self.files_found_label.setText(f"Найдено {count} исполняемых файлов (для всех уже есть .i64)")
        else:
            self.files_found_label.setText(f"Найдено {count} исполняемых файлов (не для всех есть .i64)")

        any_idb = any(self._get_expected_idb_path(f).exists() for f in files)
        self.json_export_btn.setEnabled(any_idb)
        self.html_generate_btn.setEnabled(False)

        # Обновляем treemap
        items = []
        for f in files:
            size = f.stat().st_size if f.exists() else 0
            status = 'not_analyzed'
            if self._get_expected_idb_path(f).exists():
                status = 'success'
            items.append({'name': f.name, 'size': size, 'status': status, 'path': str(f)})
        self.treemap.set_data(items)

    def _get_expected_idb_path(self, file_path: Path) -> Path:
        arch = IDAAnalyzer()._detect_arch(file_path)
        ext = ".idb" if arch == 32 else ".i64"
        return file_path.parent / (file_path.name + ext)

    def _all_idbs_exist(self, files: List[Path]) -> bool:
        return all(self._get_expected_idb_path(f).exists() for f in files)

    # ------------------------------------------------------------------
    # Запуск анализа
    # ------------------------------------------------------------------
    def _start_analysis(self):
        idat_path = get_ida_executable()
        if not shutil.which(idat_path):
            QMessageBox.warning(
                self,
                "Утилита IDA не найдена",
                f"Исполняемый файл '{idat_path}' не найден в системном PATH.\n\n"
                "Пожалуйста, проверьте путь к idat.exe в разделе «Конфигурация» или "
                "добавьте папку с IDA в переменную PATH."
            )
            return

        input_dir = self.inputdir_edit.text().strip()
        if not input_dir:
            QMessageBox.warning(self, "Ошибка", "Укажите директорию с файлами.")
            return
        if not os.path.isdir(input_dir):
            QMessageBox.critical(self, "Ошибка", "Директория не существует.")
            return

        extensions = self._selected_extensions()
        files = find_executables(input_dir, extensions=extensions)
        if not files:
            QMessageBox.information(self, "Информация", "Не найдено подходящих файлов.")
            return

        if self._all_idbs_exist(files):
            reply = QMessageBox.question(
                self,
                "Базы данных уже существуют",
                "Для всех найденных исполняемых файлов уже существуют .i64 базы.\n"
                "Хотите сразу создать JSON для последующей обработки?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._start_json_export()
                return

        self.files_found_label.setText(f"Найдено {len(files)} исполняемых файлов")

        self.analysis_in_progress = True
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.json_export_btn.setEnabled(False)
        self.html_generate_btn.setEnabled(False)
        self.current_file_label.setText("Запуск...")
        self.progress_bar.setValue(0)
        self.error_text.clear()

        self.worker = AnalysisWorker(
            files, idat_path, self.max_ida_slider.value(),
            output_dir=None,
            cleanup=self.cleanup_check.isChecked(),
            temp_cleanup=self.temp_cleanup_check.isChecked(),
            verbose=self.verbose_check.isChecked()
        )
        self.worker.progress_updated.connect(self._on_progress)
        self.worker.file_started.connect(self._on_file_started)      # новинка
        self.worker.file_completed.connect(self._on_file_completed)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.analysis_finished.connect(self._on_finished)
        self.worker.start()

    def _on_file_started(self, filename: str):
        if not filename:
            return
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), 'in_progress')
                break

    def _on_progress(self, filename: str, current: int, total: int):
        self.current_file_label.setText(f"Анализ файла {current} из {total}: {filename}")
        self.progress_bar.setValue(int(100 * current / total))

    def _on_file_completed(self, filename: str, success: bool):
        if not filename:
            return
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), 'success' if success else 'error')
                break

    def _on_error(self, message: str):
        self.error_text.append(message)

    def _on_finished(self, succeeded: int, total: int):
        self.analysis_in_progress = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.json_export_btn.setEnabled(True)
        self.html_generate_btn.setEnabled(False)
        failed = total - succeeded
        self.current_file_label.setText(f"Завершено. Успешно: {succeeded}, с ошибкой: {failed}")
        self.progress_bar.setValue(100)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
        self._refresh_file_list()

    def _cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self.current_file_label.setText("Отмена...")

    # ------------------------------------------------------------------
    # Экспорт в JSON
    # ------------------------------------------------------------------
    def _start_json_export(self):
        input_dir = self.inputdir_edit.text().strip()
        if not os.path.isdir(input_dir):
            QMessageBox.warning(self, "Ошибка", "Папка не найдена.")
            return

        idb_files = list(Path(input_dir).rglob("*.i64")) + list(Path(input_dir).rglob("*.idb"))
        if not idb_files:
            QMessageBox.information(self, "Информация", "В папке нет файлов .i64 или .idb.")
            return

        script_path = Path(__file__).resolve().parent.parent / "scripts" / "export_data.py"
        if not script_path.exists():
            QMessageBox.critical(self, "Ошибка", f"Скрипт не найден: {script_path}")
            return

        if self.pseudocode_check.isChecked():
            os.environ['IDA_PSEUDOCODE'] = '1'
        else:
            os.environ.pop('IDA_PSEUDOCODE', None)

        self.export_in_progress = True
        self.json_export_btn.setEnabled(False)
        self.html_generate_btn.setEnabled(False)
        self.json_export_label.setText("Запуск экспорта JSON...")
        self.json_progress_bar.setValue(0)
        self.error_text.clear()

        max_workers = self.max_ida_slider.value()
        idat_path = get_ida_executable()

        self.export_worker = ExportWorker(
            idb_files, script_path, idat_path, max_workers
        )
        self.export_worker.progress_updated.connect(self._on_json_export_progress)
        self.export_worker.error_occurred.connect(self._on_error)
        self.export_worker.finished.connect(self._on_json_export_finished)
        self.export_worker.start()

    def _on_json_export_progress(self, filename: str, current: int, total: int):
        self.json_export_label.setText(f"Экспорт: {current}/{total} – {filename}")
        self.json_progress_bar.setValue(int(100 * current / total))

    def _on_json_export_finished(self, succeeded: int, total: int):
        self.export_in_progress = False
        self.json_export_label.setText(f"Экспорт JSON завершён. Успешно: {succeeded}/{total}")
        self.json_progress_bar.setValue(100)
        self._export_results = self.export_worker.results if self.export_worker else {}
        self._export_succeeded = succeeded
        self._export_total = total
        self.html_generate_btn.setEnabled(True)
        os.environ.pop('IDA_PSEUDOCODE', None)
        self.html_progress_label.setText("Готов к созданию HTML")

    # ------------------------------------------------------------------
    # Генерация HTML-отчётов
    # ------------------------------------------------------------------
    def _start_html_generation(self):
        results = self._export_results
        if not results:
            QMessageBox.warning(self, "Ошибка", "Нет данных экспорта. Сначала запустите IDAtoJSON.")
            return

        generator = ReportGenerator()
        delete_json = self.delete_json_check.isChecked()

        input_dir = Path(self.inputdir_edit.text().strip())
        ida_reports = input_dir.parent / "IDAReports"
        ida_reports.mkdir(parents=True, exist_ok=True)

        self.html_in_progress = True
        self.html_generate_btn.setEnabled(False)
        self.json_export_btn.setEnabled(False)
        self.html_progress_bar.setValue(0)
        self.html_spinner.setVisible(False)
        self.error_text.clear()

        self.html_worker = HtmlGeneratorWorker(
            results, generator, ida_reports, input_dir, delete_json
        )
        self.html_worker.progress_updated.connect(self._on_html_generation_progress)
        self.html_worker.error_occurred.connect(self._on_error)
        self.html_worker.finished.connect(self._on_html_generation_finished)
        self.html_worker.start()

    def _on_html_generation_progress(self, current: int, total: int, message: str = ""):
        self.html_progress_label.setText(f"Создание HTML: {current}/{total} {message}")
        self.html_progress_bar.setValue(int(100 * current / total))

    def _on_html_generation_finished(self, generated_count: int, report_links: list,
                                     global_modules_set: set, global_elf_set: set,
                                     ida_info: dict, ida_reports: Path, input_dir: Path):
        self.html_progress_bar.setVisible(False)
        self.html_spinner.setVisible(True)
        self.html_progress_label.setText("Создание сводного отчёта...")

        sorted_modules = sorted(global_modules_set)
        sorted_elf = sorted(global_elf_set)

        self.index_worker = IndexWorker(
            ReportGenerator(), ida_reports, input_dir,
            report_links, sorted_modules, ida_info,
            sorted_elf
        )
        self.index_worker.finished.connect(
            lambda success: self._on_index_finished(success, generated_count, ida_reports, input_dir)
        )
        self.index_worker.error_occurred.connect(self._on_error)
        self.index_worker.start()

    def _on_index_finished(self, success: bool, generated_count: int, ida_reports: Path, input_dir: Path):
        self.html_spinner.setVisible(False)
        self.html_progress_bar.setVisible(True)
        self.html_progress_bar.setValue(100)
        self.html_in_progress = False
        self.html_generate_btn.setEnabled(False)
        self.json_export_btn.setEnabled(True)
        self.html_progress_label.setText(f"Готово. Создано отчётов: {generated_count}")
        if generated_count == self._export_succeeded and self._export_total > 0:
            QMessageBox.information(self, "Готово", f"Отчёты сохранены в {ida_reports}")
        else:
            QMessageBox.warning(self, "Внимание", f"Успешных отчётов: {generated_count}/{self._export_succeeded}.")

    def _safe_clean_file(self, file_path: Path, description: str = "", retries: int = 3, delay: float = 1.0):
        if not file_path.exists():
            return
        for attempt in range(1, retries + 1):
            try:
                file_path.unlink()
                print(f"[Cleanup] Removed {description}: {file_path.name}")
                return
            except PermissionError as e:
                if attempt < retries:
                    print(f"[Cleanup] Could not remove {file_path.name} (attempt {attempt}): {e}. Retrying...")
                    time.sleep(delay)
                else:
                    print(f"[Cleanup] Could not remove {file_path.name} after {retries} attempts: {e}")
            except Exception as e:
                print(f"[Cleanup] Could not remove {file_path.name}: {e}")
                break

    def _on_config_changed(self, new_config):
        self.cfg = new_config
        new_theme = new_config.get("theme", "light")
        if new_theme != self.current_theme:
            self.current_theme = new_theme
            apply_theme(QApplication.instance(), new_theme)
            self._update_menu_styles()


class HtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    finished = Signal(int, list, set, set, dict, Path, Path)
    error_occurred = Signal(str)

    def __init__(self, results: dict, generator: ReportGenerator,
                 reports_dir: Path, input_dir: Path, delete_json: bool, parent=None):
        super().__init__(parent)
        self.results = results
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.delete_json = delete_json

    def run(self):
        report_links = []
        global_modules_set = set()
        global_elf_set = set()
        ida_info = None
        generated_count = 0
        total = len(self.results)

        for i, (idb_path, success) in enumerate(self.results.items()):
            if not success:
                continue
            json_path = Path(str(idb_path) + ".export.json")
            if not json_path.exists():
                self.error_occurred.emit(f"JSON не найден: {json_path}")
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if ida_info is None and "ida_info" in data:
                    ida_info = data["ida_info"]
                for imp in data.get("imports", []):
                    mod = imp.get("module")
                    if not mod or mod.lower() == "unknown":
                        continue
                    if mod.startswith("."):
                        global_elf_set.add(mod)
                    else:
                        global_modules_set.add(mod)
                original_file = Path(data["file_name"]).name
                source_full = Path(data["file_name"])
                if not source_full.is_absolute():
                    source_full = self.input_dir / source_full
                try:
                    rel = source_full.relative_to(self.input_dir)
                except ValueError:
                    rel = Path(original_file)
                out_rel = rel.with_suffix(rel.suffix + ".html")
                output_html = self.reports_dir / out_rel
                output_html.parent.mkdir(parents=True, exist_ok=True)
                self.generator.generate_from_json(json_path, output_html, reports_dir=self.reports_dir)
                link = out_rel.as_posix()
                display = rel.as_posix()
                report_links.append({"filename": link, "display_name": display})
                generated_count += 1
                if self.delete_json:
                    json_path.unlink(missing_ok=True)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка генерации отчёта для {idb_path.name}: {e}")
            self.progress_updated.emit(i+1, total, "")
        self.finished.emit(generated_count, report_links, global_modules_set,
                           global_elf_set, ida_info, self.reports_dir, self.input_dir)