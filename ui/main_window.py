"""Главное окно приложения с боковым меню и стеком страниц."""
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QSizePolicy,
    QPushButton, QLabel, QProgressBar, QTextEdit, QGroupBox,
    QFileDialog, QStackedWidget, QMessageBox, QApplication, QLineEdit,
    QFormLayout, QSlider, QRadioButton, QButtonGroup, QGridLayout,
    QCheckBox, QFrame, QWhatsThis, QStyle
)
from PySide6.QtCore import Qt, QPoint, QThread, Signal
from pathlib import Path
from typing import List
import os
import json
import shutil
import time

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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDA Batch Tool")
        self.resize(1100, 750)
        self.cfg = load_config()
        self.current_theme = self.cfg.get("theme", "light")
        self.analysis_in_progress = False
        self.export_in_progress = False
        self.worker = None
        self.export_worker = None
        self.active_page = 0  # 0 = анализ, 1 = конфигурация

        self._build_ui()
        self._connect_signals()
        apply_theme(QApplication.instance(), self.current_theme)
        # Принудительно фиксируем состояние кнопок после глобальной темы
        self.btn_analysis.setChecked(True)
        self.btn_settings.setChecked(False)
        self._update_menu_styles()

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

        left_column.addWidget(scan_group)
        left_column.addStretch()

        # Правая колонка
        right_column = QVBoxLayout()
        right_column.setSpacing(10)
        right_column.setContentsMargins(0, 0, 0, 0)

        # Прогресс анализа (включает поле ошибок)
        progress_group = QGroupBox("Прогресс анализа")
        progress_layout = QVBoxLayout(progress_group)
        self.current_file_label = QLabel("Готов к запуску")
        self.files_found_label = QLabel("")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.current_file_label)
        progress_layout.addWidget(self.files_found_label)
        progress_layout.addWidget(self.progress_bar)

        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(120)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        progress_layout.addWidget(self.error_text)

        right_column.addWidget(progress_group)

        # Параметры отчёта
        report_group = QGroupBox("Параметры отчёта")
        report_layout = QVBoxLayout(report_group)

        self.report_progress_label = QLabel("Готов к созданию отчётов")
        self.report_progress_bar = QProgressBar()
        self.report_progress_bar.setRange(0, 100)

        self.delete_json_check = QCheckBox("Удалить JSON-файлы после создания отчётов")
        self.delete_json_check.setToolTip("После успешной генерации HTML-отчётов, JSON-файлы экспорта будут удалены.")

        self.export_report_btn = QPushButton("Создать HTML-отчёты из .i64")
        self.export_report_btn.setEnabled(False)
        self.export_report_btn.setToolTip(
            "Запустить IDAPython-скрипт экспорта данных на всех .i64 файлах "
            "и создать интерактивные HTML-отчёты."
        )

        report_layout.addWidget(self.report_progress_label)
        report_layout.addWidget(self.report_progress_bar)
        report_layout.addWidget(self.delete_json_check)
        report_layout.addWidget(self.export_report_btn, alignment=Qt.AlignLeft)
        right_column.addWidget(report_group)
        right_column.addStretch()

        columns_layout.addLayout(left_column, 1)
        columns_layout.addLayout(right_column, 1)
        layout.addLayout(columns_layout)

        layout.addStretch()
        return page

    def _connect_signals(self):
        self.btn_analysis.clicked.connect(lambda: self.switch_page(0))
        self.btn_settings.clicked.connect(lambda: self.switch_page(1))
        self.browse_dir_btn.clicked.connect(self._browse_input_dir)
        self.start_btn.clicked.connect(self._start_analysis)
        self.cancel_btn.clicked.connect(self._cancel_analysis)
        self.export_report_btn.clicked.connect(self._export_and_generate_reports)

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

    def _selected_extensions(self):
        checked = self.platform_buttons.checkedButton()
        if checked and checked in self.radio_to_platform:
            return PLATFORM_EXTENSIONS[self.radio_to_platform[checked]]["exts"]
        return PLATFORM_EXTENSIONS["All platforms"]["exts"]

    def _start_analysis(self):
        idat_path = get_ida_executable()
        if not shutil.which(idat_path):
            QMessageBox.warning(
                self,
                "Утилита IDA не найдена",
                f"Исполняемый файл '{idat_path}' не найден в системном PATH.\n\n"
                "Пожалуйста, проверьте путь к idat.exe в разделе «Конфигурация» или добавьте папку с IDA в переменную PATH."
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
        max_workers = self.max_ida_slider.value()

        files = find_executables(input_dir, extensions=extensions)
        if not files:
            QMessageBox.information(self, "Информация", "Не найдено подходящих файлов.")
            return

        self.files_found_label.setText(f"Найдено {len(files)} исполняемых файлов")

        self.analysis_in_progress = True
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.export_report_btn.setEnabled(False)
        self.current_file_label.setText("Запуск...")
        self.progress_bar.setValue(0)
        self.error_text.clear()

        self.worker = AnalysisWorker(
            files, idat_path, max_workers,
            output_dir=Path(input_dir),
            cleanup=self.cleanup_check.isChecked(),
            temp_cleanup=self.temp_cleanup_check.isChecked(),
            verbose=self.verbose_check.isChecked()
        )
        self.worker.progress_updated.connect(self._on_progress)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.analysis_finished.connect(self._on_finished)
        self.worker.start()

    def _on_progress(self, filename: str, current: int, total: int):
        self.current_file_label.setText(f"Анализ файла {current} из {total}: {filename}")
        self.progress_bar.setValue(int(100 * current / total))

    def _on_error(self, message: str):
        self.error_text.append(message)

    def _on_finished(self, succeeded: int, total: int):
        self.analysis_in_progress = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.export_report_btn.setEnabled(True)
        failed = total - succeeded
        self.current_file_label.setText(f"Завершено. Успешно: {succeeded}, с ошибкой: {failed}")
        self.progress_bar.setValue(100)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

    def _cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self.current_file_label.setText("Отмена...")

    # ------------------------------------------------------------------
    # Экспорт и генерация отчётов
    # ------------------------------------------------------------------
    def _export_and_generate_reports(self):
        input_dir = self.inputdir_edit.text().strip()
        if not os.path.isdir(input_dir):
            QMessageBox.warning(self, "Ошибка", "Папка не найдена.")
            return

        idb_files = list(Path(input_dir).glob("*.i64")) + list(Path(input_dir).glob("*.idb"))
        if not idb_files:
            QMessageBox.information(self, "Информация", "В папке нет файлов .i64 или .idb.")
            return

        script_path = Path(__file__).resolve().parent.parent / "scripts" / "export_data.py"
        if not script_path.exists():
            QMessageBox.critical(self, "Ошибка", f"Скрипт не найден: {script_path}")
            return

        self.export_in_progress = True
        self.export_report_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.report_progress_label.setText("Запуск экспорта данных...")
        self.report_progress_bar.setValue(0)
        self.error_text.clear()

        max_workers = self.max_ida_slider.value()
        idat_path = get_ida_executable()

        self.export_worker = ExportWorker(
            idb_files, script_path, idat_path, max_workers
        )
        self.export_worker.progress_updated.connect(self._on_export_progress)
        self.export_worker.error_occurred.connect(self._on_error)
        self.export_worker.finished.connect(self._on_export_finished)
        self.export_worker.start()

    def _on_export_progress(self, filename: str, current: int, total: int):
        self.report_progress_label.setText(f"Экспорт: {current}/{total} – {filename}")
        self.report_progress_bar.setValue(int(100 * current / total))

    def _on_export_finished(self, succeeded: int, total: int):
        results = self.export_worker.results if self.export_worker else {}
        generator = ReportGenerator()
        delete_json = self.delete_json_check.isChecked()

        input_dir = Path(self.inputdir_edit.text().strip())
        reports_dir = input_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        generated_html_files = []
        global_modules_set = set()
        ida_info = None

        generated_count = 0
        for idb_path, success in results.items():
            if not success:
                continue

            json_path = Path(str(idb_path) + ".export.json")
            if not json_path.exists():
                self._on_error(f"JSON не найден: {json_path}")
                continue

            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if ida_info is None and "ida_info" in data:
                    ida_info = data["ida_info"]

                for imp in data.get("imports", []):
                    mod = imp.get("module")
                    if mod and mod.lower() != "unknown":
                        global_modules_set.add(mod)

                original_file = Path(data["file_name"]).name
                html_name = original_file + ".html"
                output_html = reports_dir / html_name

                generator.generate_from_json(json_path, output_html)
                generated_html_files.append(output_html)
                generated_count += 1

                if delete_json:
                    json_path.unlink(missing_ok=True)
            except Exception as e:
                self._on_error(f"Ошибка генерации отчёта для {idb_path.name}: {e}")

        # Удаляем временные файлы экспорта
        for idb_path, success in results.items():
            if not success:
                continue
            out_dir = idb_path.parent
            script_log = out_dir / (idb_path.stem + "_script.log")
            self._safe_clean_file(script_log, "script log")
            for temp_pat in ["*.id0", "*.id1", "*.nam", "*.til"]:
                for temp_file in out_dir.glob(temp_pat):
                    self._safe_clean_file(temp_file, temp_pat[1:])

        if generated_html_files:
            try:
                sorted_modules = sorted(global_modules_set)
                generator.generate_index(
                    reports_dir,
                    input_dir,
                    generated_html_files,
                    sorted_modules,
                    ida_info
                )
            except Exception as e:
                self._on_error(f"Ошибка создания сводного отчёта: {e}")

        self.export_in_progress = False
        self.export_report_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.report_progress_label.setText(f"Готово. Создано отчётов: {generated_count}")
        self.report_progress_bar.setValue(100)
        if generated_count == succeeded and total > 0:
            QMessageBox.information(self, "Готово", f"Отчёты сохранены в {reports_dir}")
        else:
            QMessageBox.warning(self, "Внимание", f"Успешных отчётов: {generated_count}/{succeeded}.")

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