"""
Пример IDAPython скрипта, который можно запустить через IDAAnalyzer.
Переименовывает самые большие функции в префикс big_func_.
"""
import idaapi
import idautils
import idc

def main():
    idaapi.auto_wait()
    funcs = []
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if func:
            funcs.append((func.size(), ea, idc.get_func_name(ea)))
    funcs.sort(reverse=True)
    renamed = 0
    for i, (size, ea, name) in enumerate(funcs):
        if i >= 5:
            break
        new_name = f"big_func_{i}_{size}"
        idc.set_name(ea, new_name, idc.SN_NOWARN)
        renamed += 1
    print(f"Renamed {renamed} functions.")
    idc.qexit(0)

if __name__ == "__main__":
    main()