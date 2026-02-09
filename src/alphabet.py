def sym2num(sym: str) -> int:
    """По алгоритму из псевдокода, но с Ы в алфавите."""
    if len(sym) != 1:
        raise ValueError("Должен быть один символ")
    tmp = ord(sym)
    if tmp == 95:  # '_'
        return 0
    out = tmp - 1039
    if tmp > 1065:  # если символ после Щ (т.е. пропускаем Ъ)
        out -= 1
    return out

def num2sym(num: int) -> str:
    """Обратное преобразование."""
    if num == 0:
        return '_'
    code = num + 1039
    if num > 26:  # если номер больше 26 (т.е. Щ и дальше)
        code += 1  # компенсируем пропуск Ъ
    return chr(code)

alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЫЬЭЮЯ_"

# Проверяем преобразование
for i, ch in enumerate(alphabet, 1):
    if ch == '_':
        num = 0
    else:
        num = i
    # Прямое преобразование
    calc_num = sym2num(ch)
    # Обратное
    calc_ch = num2sym(calc_num)
    print(f"{ch} -> {calc_num} -> {calc_ch} : {ch == calc_ch}")

def add_s(s1: str, s2: str) -> str:
    tmp = sym2num(s1) + sym2num(s2)
    return num2sym(tmp % 32)

def sub_s(s1: str, s2: str) -> str:
    tmp = sym2num(s1) - sym2num(s2) + 32
    return num2sym(tmp % 32)


def add_txt(T1: str, T2: str) -> str:
    out = ""
    m = min(len(T1), len(T2))
    if len(T1) > len(T2):
        T_IN = T1
    else:
        T_IN = T2
    M = len(T_IN)

    for i in range(m):
        t1 = T1[i]
        t2 = T2[i]
        out += add_s(t1, t2)

    if M > m:
        for i in range(m, M):
            out += T_IN[i]

    return out


def sub_txt(T1: str, T2: str) -> str:
    out = ""
    m = min(len(T1), len(T2))
    if len(T1) > len(T2):
        T_IN = T1
        flag = 0
    else:
        T_IN = T2
        flag = 1
    M = len(T_IN)

    for i in range(m):
        t1 = T1[i]
        t2 = T2[i]
        out += sub_s(t1, t2)

    if M > m:
        for i in range(m, M):
            t = T_IN[i]
            if flag == 1:
                out += sub_s("_", t)
            else:
                out += sub_s(t, "_")

    return out

print("add_s('Я', 'Ж') =", add_s('Я', 'Ж'))  # Е
print("sub_s('Е', 'Ж') =", sub_s('Е', 'Ж'))  # Я

T1 = "ЕЖИК"
T2 = "В_ТУМАНЕ"
print(f"add_txt('{T1}', '{T2}') =", add_txt(T1, T2))
print(f"sub_txt('{T1}', '{T2}') =", sub_txt(T1, T2))