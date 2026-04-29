"""
Модуль поиска исполняемых файлов.
Поддерживает фильтрацию по расширениям и базовую проверку сигнатур PE/ELF.
"""
import os
from pathlib import Path
from typing import List, Optional

# Сигнатуры для быстрого определения типа файла (первые байты)
MZ_SIGNATURE = b'MZ'
ELF_SIGNATURE = b'\x7fELF'

def is_executable(file_path: Path) -> bool:
    """Проверяет, является ли файл исполняемым (PE или ELF) по сигнатуре."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        if len(header) < 4:
            return False
        if header[:2] == MZ_SIGNATURE:          # Windows PE (EXE, DLL, SYS и т.д.)
            return True
        if header[:4] == ELF_SIGNATURE:         # Linux ELF
            return True
        # Можно добавить другие форматы (Mach-O, etc.)
    except (OSError, PermissionError):
        pass
    return False

def find_executables(
    root_dir: str,
    extensions: Optional[List[str]] = None,
    use_signatures: bool = False
) -> List[Path]:
    """
    Рекурсивно находит все исполняемые файлы в каталоге.
    - extensions: список расширений без точки (например ['.exe', '.dll']).
      Если не указан, ищет любые файлы, похожие на исполняемые (по сигнатурам, если use_signatures=True).
    - use_signatures: если True, проверяет сигнатуры даже при указанных расширениях.
    """
    root = Path(root_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"{root_dir} is not a valid directory")

    matched = []
    for entry in root.rglob('*'):
        if not entry.is_file():
            continue
        if extensions:
            if entry.suffix.lower() in extensions:
                if use_signatures and not is_executable(entry):
                    continue
                matched.append(entry)
        else:
            # Без фильтра расширений — проверяем сигнатуры или просто берём все?
            # В духе idahunt: без фильтра он считает исполняемыми всё, что IDA сможет открыть.
            # Здесь оставим разумный компромисс: либо по сигнатурам, либо все подряд (но это опасно).
            if use_signatures:
                if is_executable(entry):
                    matched.append(entry)
            else:
                matched.append(entry)   # потенциально много "мусора"
    return matched

def default_filter() -> str:
    """Строка фильтра по умолчанию, аналогичная idahunt."""
    return ".exe,.dll,.elf,.so,.sys,.bin"