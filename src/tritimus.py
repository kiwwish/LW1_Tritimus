
from alphabet import sym2num, num2sym


class TrithemusCipher:
    """Класс для простого шифра Тритемуса"""

    def __init__(self, key: str):
        self.key = key.upper()
        self.table = self._build_table()

    def _build_table(self) -> str:
        """Построение таблицы замены по ключу"""
        out = ""
        A = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЫЬЭЮЯ_"
        for i in range(len(self.key)):
            tmp = self.key[i]
            while tmp in out:
                tmp_num = sym2num(tmp)
                tmp = num2sym((tmp_num + 1) % 32)
            if len(out) < 32:
                out += tmp

        for ch in A:
            if ch not in out:
                out += ch

        return out

    def encrypt(self, text: str) -> str:
        """Шифрование текста"""
        out = ""
        text = text.upper()
        for i in range(len(text)):
            ch = text[i]
            pos = self.table.find(ch)
            if pos == -1:
                out += ch
            else:
                new_pos = (pos + 8) % 32
                out += self.table[new_pos]
        return out

    def decrypt(self, cipher: str) -> str:
        """Дешифрование текста"""
        out = ""
        cipher = cipher.upper()
        for i in range(len(cipher)):
            ch = cipher[i]
            pos = self.table.find(ch)
            if pos == -1:
                out += ch
            else:
                new_pos = (pos - 8) % 32
                out += self.table[new_pos]
        return out

    def get_table(self) -> str:
        """Получить таблицу замены"""
        return self.table