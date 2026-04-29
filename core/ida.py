"""
Управление запуском IDA Pro в пакетном режиме.
Поддерживает параллельный анализ файлов и выполнение скриптов на готовых .i64.
"""
import subprocess
import time
import logging
import os
import struct
from pathlib import Path
from typing import List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import get_ida_executable, get_max_ida

logger = logging.getLogger(__name__)


class IDAAnalyzer:
    """
    Класс для пакетного анализа файлов в IDA Pro.
    """

    def __init__(self, idat_path: Optional[str] = None, max_workers: Optional[int] = None):
        self.idat = idat_path or get_ida_executable()
        self.max_workers = max_workers or get_max_ida()
        self._progress_callback: Optional[Callable] = None

    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        self._progress_callback = callback

    # ------------------------------------------------------------------
    # Анализ файлов (создание .i64)
    # ------------------------------------------------------------------
    def _unique_idb_path(self, file_path: Path, output_dir: Path) -> Path:
        arch = self._detect_arch(file_path)
        ext = ".idb" if arch == 32 else ".i64"
        return output_dir / (file_path.name + ext)

    def analyze_file(self, file_path: Path, output_dir: Optional[Path] = None,
                     script_path: Optional[Path] = None, keep_log_on_error: bool = True) -> bool:
        """
        Анализирует один файл. Больше не удаляет временные файлы –
        очистка будет выполнена позже в analyze_batch.
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        out_dir = output_dir or file_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        idb_path = self._unique_idb_path(file_path, out_dir)
        log_path = out_dir / (file_path.name + ".log")

        cmd = [self.idat, "-B", f"-o{idb_path}", f"-L{log_path}"]
        if script_path:
            cmd.append(f"-S{script_path}")
        cmd.append(str(file_path))

        logger.info(f"Starting IDA: {cmd}")
        success = False
        use_shell = (os.name != 'posix')

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True, shell=use_shell)
            process.wait()
            returncode = process.returncode

            temp_id0 = str(file_path) + ".id0"   # проверка краша IDA
            if os.path.isfile(temp_id0):
                logger.error(f"IDA crashed on {file_path.name}: .id0 still present")
                if keep_log_on_error and log_path.exists():
                    self._log_tail(log_path)
                success = False
            elif returncode != 0:
                logger.error(f"IDA failed on {file_path.name}: returncode = {returncode}")
                if keep_log_on_error and log_path.exists():
                    self._log_tail(log_path)
                success = False
            else:
                if idb_path.exists():
                    success = True
                else:
                    logger.error(f"Database not created for {file_path.name}: {idb_path}")
                    success = False
        except Exception as e:
            logger.exception(f"Error running IDA for {file_path.name}: {e}")
            return False

        return success

    def analyze_batch(self, files: List[Path], output_dir: Optional[Path] = None,
                      script_path: Optional[Path] = None,
                      cleanup_temp: bool = True, temp_cleanup: bool = True) -> dict:
        """
        Пакетный анализ с отложенной очисткой временных файлов.
        """
        total = len(files)
        results = {}
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(
                    self.analyze_file, f, output_dir, script_path
                ): f
                for f in files
            }
            for future in as_completed(future_to_file):
                f = future_to_file[future]
                try:
                    success = future.result()
                    results[f] = success
                except Exception as e:
                    logger.error(f"Error during analysis of {f}: {e}")
                    results[f] = False
                completed += 1
                if self._progress_callback:
                    self._progress_callback(f.name, completed, total)

        # Удаляем временные файлы только после полного завершения всех анализов
        if cleanup_temp or temp_cleanup:
            logger.info("Starting delayed cleanup of temporary files...")
            for f, success in results.items():
                if not success:
                    continue
                out_dir = output_dir or f.parent
                idb_path = self._unique_idb_path(f, out_dir)
                log_path = out_dir / (f.name + ".log")
                if cleanup_temp:
                    self._safe_clean_file(log_path, "log")
                    asm_path = idb_path.with_suffix('.asm')
                    self._safe_clean_file(asm_path, "asm")
                if temp_cleanup:
                    for pattern in ["*.id0", "*.id1", "*.nam", "*.til"]:
                        for temp_file in out_dir.glob(pattern):
                            self._safe_clean_file(temp_file, pattern[1:])

        return results

    # ------------------------------------------------------------------
    # Выполнение скрипта на существующих .i64/.idb
    # ------------------------------------------------------------------
    def run_script_on_idb(self, idb_path: Path, script_path: Path,
                          output_dir: Optional[Path] = None) -> bool:
        if not idb_path.exists():
            logger.error(f"Database not found: {idb_path}")
            return False
        if not script_path.exists():
            logger.error(f"Script not found: {script_path}")
            return False

        out_dir = output_dir or idb_path.parent
        log_path = out_dir / (idb_path.stem + "_script.log")

        cmd = [
            self.idat,
            "-A",
            f"-S{script_path}",
            f"-L{log_path}",
            str(idb_path)
        ]

        logger.info(f"Running script on {idb_path.name}: {cmd}")
        use_shell = (os.name != 'posix')
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True, shell=use_shell)
            process.wait()
            ret = process.returncode
            if ret != 0:
                logger.error(f"Script failed on {idb_path.name}: returncode={ret}")
                self._log_tail(log_path)
                return False
            return True
        except Exception as e:
            logger.exception(f"Error running script on {idb_path.name}: {e}")
            return False

    def run_script_on_batch(self, idb_files: List[Path], script_path: Path,
                            output_dir: Optional[Path] = None) -> dict:
        total = len(idb_files)
        results = {}
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.run_script_on_idb, f, script_path, output_dir): f
                for f in idb_files
            }
            for future in as_completed(future_to_file):
                f = future_to_file[future]
                try:
                    success = future.result()
                    results[f] = success
                except Exception as e:
                    logger.error(f"Error running script on {f}: {e}")
                    results[f] = False
                completed += 1
                if self._progress_callback:
                    self._progress_callback(f.name, completed, total)

        return results

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def _safe_clean_file(self, file_path: Path, description: str = "", retries: int = 3, delay: float = 1.0):
        """Пытается удалить файл несколько раз с задержкой."""
        if not file_path.exists():
            return
        for attempt in range(1, retries + 1):
            try:
                file_path.unlink()
                logger.info(f"Removed {description}: {file_path.name}")
                return
            except PermissionError as e:
                if attempt < retries:
                    logger.warning(f"Could not remove {file_path.name} (attempt {attempt}): {e}. Retrying...")
                    time.sleep(delay)
                else:
                    logger.warning(f"Could not remove {file_path.name} after {retries} attempts: {e}")
            except Exception as e:
                logger.warning(f"Could not remove {file_path.name}: {e}")
                break

    def _detect_arch(self, file_path: Path) -> int:
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            if magic[:4] == b'\x7fELF':
                f.seek(0)
                elf_class = f.read(5)[4]
                return 32 if elf_class == 1 else 64
            if magic[:2] == b'MZ':
                f.seek(60)
                s = f.read(4)
                header_offset = struct.unpack("<L", s)[0]
                f.seek(header_offset + 4)
                s = f.read(2)
                machine = struct.unpack("<H", s)[0]
                if machine == 0x014c: return 32
                elif machine == 0x8664: return 64
        except Exception:
            pass
        return 64

    def _log_tail(self, log_path: Path, lines: int = 10):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                log_lines = f.readlines()
            if log_lines:
                logger.error("Last lines from IDA log:\n" + "".join(log_lines[-lines:]))
        except Exception as e:
            logger.warning(f"Could not read log: {e}")