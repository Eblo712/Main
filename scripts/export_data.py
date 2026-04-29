"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>
Совместим с IDA Pro 9.3.
"""
import json
import idaapi
import idautils
import idc
import ida_nalt
import ida_entry

def export_to_json(output_path=None):
    idaapi.auto_wait()
    if output_path is None:
        idb_path = idc.get_idb_path()
        output_path = idb_path + ".export.json"
        print(f"[IDAPython] Output will be: {output_path}")

    # Собираем информацию о версии IDA
    ida_version = idaapi.get_kernel_version()
    # Дополнительные характеристики можно добавить по желанию
    ida_info = {
        "kernel_version": ida_version,
        "sdk_version": idaapi.IDA_SDK_VERSION,
    }

    data = {
        "file_name": idc.get_input_file_path(),
        "ida_info": ida_info,
        "functions": [],
        "imports": [],
        "exports": []
    }

    # Функции (все)
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()

        instructions = []
        for head in idautils.Heads(ea, ea + size):
            disasm_line = idc.GetDisasm(head)
            instructions.append({
                "address": f"0x{head:X}",
                "instruction": disasm_line
            })

        raw = idc.get_bytes(ea, size)
        hexdump_lines = []
        if raw:
            for i in range(0, len(raw), 16):
                chunk = raw[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hexdump_lines.append(f"{ea + i:08X}  {hex_part:<48}  {ascii_part}")

        data["functions"].append({
            "name": name,
            "start_ea": f"0x{ea:X}",
            "size": size,
            "instructions": instructions,
            "hexdump": "\n".join(hexdump_lines)
        })

    # Импорты
    try:
        import_module_count = ida_nalt.get_import_module_qty()
    except AttributeError:
        print("[IDAPython] ida_nalt.get_import_module_qty() not available, skipping imports.")
        import_module_count = 0

    for mod_index in range(import_module_count):
        try:
            module_name = ida_nalt.get_import_module_name(mod_index)
        except AttributeError:
            module_name = "unknown"

        def callback(ea, name, ordinal):
            if name:
                data["imports"].append({
                    "name": name,
                    "module": module_name,
                    "address": f"0x{ea:X}"
                })
            return True

        try:
            ida_nalt.enum_import_names(mod_index, callback)
        except AttributeError:
            print(f"[IDAPython] ida_nalt.enum_import_names() not available for module {module_name}.")

    # Экспорты
    try:
        entry_qty = ida_entry.get_entry_qty()
        for i in range(entry_qty):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if ea != idaapi.BADADDR and name:
                data["exports"].append({
                    "name": name,
                    "address": f"0x{ea:X}",
                    "ordinal": ordinal
                })
    except AttributeError:
        print("[IDAPython] ida_entry module not available, skipping exports.")

    # Сортировка
    data["functions"].sort(key=lambda f: int(f["start_ea"], 16))
    data["exports"].sort(key=lambda e: e["ordinal"])

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Данные экспортированы в {output_path}")
    idc.qexit(0)

if __name__ == "__main__":
    export_to_json()