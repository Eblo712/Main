"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>
Совместим с IDA Pro 9.3.
Псевдокод добавляется только при установленной переменной окружения IDA_PSEUDOCODE=1.
"""
import json
import os
import idaapi
import idautils
import idc
import ida_nalt
import ida_bytes

def _is_elf_file() -> bool:
    try:
        raw = ida_bytes.get_bytes(0, 4)
        return raw[:4] == b'\x7fELF'
    except Exception:
        return False

def _format_hexdump_with_ascii(data: bytes, start_addr: int = 0) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        addr = f'{start_addr + offset:08x}'
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{addr}  {hex_part:<48}  |{ascii_part}|')
    return '\n'.join(lines)

def export_to_json(output_path=None):
    idaapi.auto_wait()
    if output_path is None:
        idb_path = idc.get_idb_path()
        output_path = idb_path + ".export.json"

    is_elf = _is_elf_file()

    data = {
        "file_name": idc.get_input_file_path(),
        "is_elf": is_elf,
        "functions": [],
        "imports": [],
        "exports": [],
        "elf_sections": [],
        "needed_libs": []
    }

    # Читаем переменную окружения, установленную GUI
    pseudocode_enabled = os.environ.get('IDA_PSEUDOCODE', '0') == '1'

    # ----------------------------------------------------------------
    # Функции (без ограничений)
    # ----------------------------------------------------------------
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()

        # Дизассемблирование: все инструкции
        instructions = []
        for head in idautils.Heads(ea, ea + size):
            mnem = idc.print_insn_mnem(head)
            op_str = idc.print_operand(head, 0)
            if mnem:
                instructions.append(f"0x{head:X}  {mnem} {op_str}")
        disassembly_text = '\n'.join(instructions)

        # Hex-дамп с ASCII
        try:
            raw = ida_bytes.get_bytes(ea, size)
            hexdump = _format_hexdump_with_ascii(raw, ea) if raw else ""
        except Exception:
            hexdump = "недоступно"

        pseudocode = ""
        if pseudocode_enabled:
            try:
                import ida_hexrays
                # Принудительно загружаем плагин декомпилятора (обязательно в пакетном режиме)
                if not idaapi.load_plugin('hexrays'):
                    print(f"[IDAPython] Не удалось загрузить плагин hexrays для {name}")
                elif ida_hexrays.init_hexrays_plugin():
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        pseudocode = str(cfunc)
                    else:
                        pseudocode = "Декомпиляция не удалась."
                else:
                    pseudocode = "Декомпилятор не инициализирован."
            except ImportError:
                pseudocode = ""
            except Exception as e:
                pseudocode = f"Ошибка декомпиляции: {e}"

    # ----------------------------------------------------------------
    # Импорты и ELF
    # ----------------------------------------------------------------
    try:
        import_module_count = ida_nalt.get_import_module_qty()
    except AttributeError:
        import_module_count = 0

    raw_imports = []
    for mod_index in range(import_module_count):
        try:
            module_name = ida_nalt.get_import_module_name(mod_index)
        except AttributeError:
            module_name = "unknown"

        def callback(ea, name, ordinal):
            if name:
                raw_imports.append({
                    "name": name,
                    "module": module_name,
                    "address": f"0x{ea:X}"
                })
            return True

        try:
            ida_nalt.enum_import_names(mod_index, callback)
        except AttributeError:
            pass

    if is_elf:
        needed = set()
        sections = set()
        for imp in raw_imports:
            mod = imp["module"]
            if mod.startswith('.'):
                sections.add(mod)
                imp["module"] = "ELF Section"
            else:
                needed.add(mod)
        data["needed_libs"] = sorted(list(needed))
        data["elf_sections"] = sorted(list(sections))
    else:
        data["needed_libs"] = []
        data["elf_sections"] = []

    data["imports"] = raw_imports

    # ----------------------------------------------------------------
    # Экспорты
    # ----------------------------------------------------------------
    exports = []
    for i in range(idc.get_entry_qty()):
        entry = idc.get_entry_ordinal(i)
        if entry != -1:
            addr = idc.get_entry(entry)
            name = idc.get_entry_name(addr)
            if name:
                exports.append({
                    "name": name,
                    "address": f"0x{addr:X}",
                    "ordinal": entry
                })

    if not exports:
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if name and not name.startswith(("sub_", "j_", "def_", "nullsub_")):
                exports.append({
                    "name": name,
                    "address": f"0x{ea:X}",
                    "ordinal": len(exports)
                })

    data["exports"] = exports
    data["functions"].sort(key=lambda f: int(f["start_ea"], 16))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Данные экспортированы в {output_path}")
    idc.qexit(0)

if __name__ == "__main__":
    export_to_json()