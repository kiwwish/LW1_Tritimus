ALPHABET_SIZE: int = 32

def verify_alphabet() -> bool:
    print("Проверка алфавита...")
    for i in range(ALPHABET_SIZE):
        ch = num2sym(i)
        j = sym2num(ch)
        if i != j:
            print(f"Ошибка: num2sym({i}) = '{ch}', sym2num('{ch}') = {j}")
            return False
    print(f"✓ Алфавит корректен: {ALPHABET_SIZE} символов")
    return True

# Определение номера символа в алфавите
def sym2num(sym: str) -> int:
    if len(sym) != 1:
        print ("Должен быть один символ")
    tmp = ord(sym)
    if tmp == 95:  # '_'
        return 0
    out = tmp - 1039
    if tmp > 1065:
        out -= 1
    return out

# Обпределенеие символа по номеру в алфавите
def num2sym(num: int) -> str:
    if num < 0 or num > 33:
        print ("Введите номер от 0 до 31")
    if num == 0:
        return '_'
    code = num + 1039
    if num > 26:  # если номер больше 26 (т.е. Щ и дальше)
        code += 1  # компенсируем пропуск Ъ
    return chr(code)

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

def text2array(text: str) -> list:
    return [sym2num(ch) for ch in text]

def array2text(arr: list) -> str:
    return ''.join(num2sym(num) for num in arr)

print (text2array('орошо_быть_вами'))
k = 'хорошо быть вами'
arr = text2array(k)
sum = 0
for i in range (16):
    sum = (24+sum+(-1)^(i)*arr[i])%24
    print(arr[i], sum + (-1)^(i) * arr[i], sum)

arr_1 = text2array('блок')
print(arr_1)