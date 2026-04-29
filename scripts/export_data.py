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

def export_to_json(output_path=None):
    idaapi.auto_wait()
    if output_path is None:
        # Получаем путь к открытой базе (например, .../7zG.exe.i64)
        idb_path = idc.get_idb_path()
        output_path = idb_path + ".export.json"
        print(f"[IDAPython] Output will be: {output_path}")

    data = {
        "file_name": idc.get_input_file_path(),
        "functions": [],
        "imports": []
    }

    # Функции
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()

        instructions = []
        for head in idautils.Heads(ea, ea + min(size, 256)):
            mnem = idc.print_insn_mnem(head)
            op_str = idc.print_operand(head, 0)
            instructions.append({
                "address": f"0x{head:X}",
                "mnem": mnem,
                "op_str": op_str
            })
            if len(instructions) >= 100:
                break

        raw = idc.get_bytes(ea, min(size, 256))
        hexdump = raw.hex(' ') if raw else ""

        data["functions"].append({
            "name": name,
            "start_ea": f"0x{ea:X}",
            "size": size,
            "instructions": instructions,
            "hexdump": hexdump
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

    data["functions"].sort(key=lambda f: int(f["start_ea"], 16))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Данные экспортированы в {output_path}")
    idc.qexit(0)

if __name__ == "__main__":
    export_to_json()