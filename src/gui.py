# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tritimus import TrithemusCipher
from polyTritimus import PolyalphabeticTrithemus, STrithemus, EnhancedSTrithemus


class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифр Тритемуса")
        self.root.geometry("1000x950")

        # Создаём вкладки
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Вкладка 1: Простой шифр Тритемуса
        self.frame_simple = ttk.Frame(self.notebook)
        self.notebook.add(self.frame_simple, text='Простой шифр Тритемуса')
        self.setup_simple_tab()

        # Вкладка 2: Полиалфавитный шифр Тритемуса
        self.frame_poly = ttk.Frame(self.notebook)
        self.notebook.add(self.frame_poly, text='Полиалфавитный шифр Тритемуса')
        self.setup_poly_tab()

        # Вкладка 3: S-блоки
        self.frame_sblock = ttk.Frame(self.notebook)
        self.notebook.add(self.frame_sblock, text='S-блоки для шифра Тритемуса')
        self.setup_sblock_tab()

        # Вкладка 4: Усиленные S-блоки
        self.frame_enhanced = ttk.Frame(self.notebook)
        self.notebook.add(self.frame_enhanced, text='Модификация S-блоков для шифра Тритимуса')
        self.setup_enhanced_tab()

    # ========== ВКЛАДКА 1: ПРОСТОЙ ШИФР ТРИТЕМУСА ==========

    def setup_simple_tab(self):
        """Настройка вкладки простого шифра Тритемуса"""
        # Стиль для кнопок (одинаковый размер)
        button_style = {'width': 20}

        # Основной фрейм с отступами
        main_frame = ttk.Frame(self.frame_simple)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # === ОБЛАСТЬ ТАБЛИЦЫ ===
        frame_table = ttk.LabelFrame(main_frame, text="Таблица замены", padding=10)
        frame_table.pack(fill='x', pady=(0, 10))

        # Первая строка: ключ и кнопка
        key_frame = ttk.Frame(frame_table)
        key_frame.pack(fill='x', pady=(0, 5))

        ttk.Label(key_frame, text="Ключ для таблицы:").pack(side='left', padx=(0, 5))
        self.key_entry = ttk.Entry(key_frame, width=40)
        self.key_entry.pack(side='left', padx=(0, 10))

        ttk.Button(key_frame, text="Построить таблицу",
                   command=self.show_table, **button_style).pack(side='left')

        # Вторая строка: таблица
        table_frame = ttk.Frame(frame_table)
        table_frame.pack(fill='x')

        ttk.Label(table_frame, text="Таблица:").pack(side='left', anchor='n', padx=(0, 5))
        self.table_text = tk.Text(table_frame, height=3, width=65,
                                  state='disabled', bg='#f0f0f0')
        self.table_text.pack(side='left')

        # === ОБЛАСТЬ ШИФРОВАНИЯ ===
        frame_encrypt = ttk.LabelFrame(main_frame, text="Шифрование", padding=10)
        frame_encrypt.pack(fill='x', pady=(0, 10))

        # Текст для шифрования
        ttk.Label(frame_encrypt, text="Текст для шифрования:").pack(anchor='w', pady=(0, 5))
        self.text_encrypt = scrolledtext.ScrolledText(frame_encrypt, height=4, width=70)
        self.text_encrypt.pack(fill='x', pady=(0, 5))

        # Кнопки шифрования
        buttons_frame_encrypt = ttk.Frame(frame_encrypt)
        buttons_frame_encrypt.pack(fill='x', pady=(0, 10))

        ttk.Button(buttons_frame_encrypt, text="Зашифровать",
                   command=self.encrypt_text, **button_style).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame_encrypt, text="Копировать шифр",
                   command=self.copy_cipher, **button_style).pack(side='left')

        # Результат шифрования
        ttk.Label(frame_encrypt, text="Результат:").pack(anchor='w', pady=(0, 5))
        self.result_encrypt = scrolledtext.ScrolledText(frame_encrypt, height=4, width=70)
        self.result_encrypt.pack(fill='x')

        # === ОБЛАСТЬ ДЕШИФРОВАНИЯ ===
        frame_decrypt = ttk.LabelFrame(main_frame, text="Дешифрование", padding=10)
        frame_decrypt.pack(fill='x')

        # Текст для дешифрования
        ttk.Label(frame_decrypt, text="Шифр для расшифровки:").pack(anchor='w', pady=(0, 5))
        self.text_decrypt = scrolledtext.ScrolledText(frame_decrypt, height=4, width=70)
        self.text_decrypt.pack(fill='x', pady=(0, 5))

        # Кнопки дешифрования (две в одной строке)
        buttons_frame_decrypt = ttk.Frame(frame_decrypt)
        buttons_frame_decrypt.pack(fill='x', pady=(0, 10))

        ttk.Button(buttons_frame_decrypt, text="Вставить из буфера",
                   command=self.paste_cipher, **button_style).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame_decrypt, text="Расшифровать",
                   command=self.decrypt_text, **button_style).pack(side='left')

        # Результат дешифрования
        ttk.Label(frame_decrypt, text="Результат:").pack(anchor='w', pady=(0, 5))
        self.result_decrypt = scrolledtext.ScrolledText(frame_decrypt, height=4, width=70)
        self.result_decrypt.pack(fill='x')

    # Методы для простого шифра
    def show_table(self):
        """Показать таблицу замены для введённого ключа"""
        key = self.key_entry.get().strip().upper()
        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return

        cipher = TrithemusCipher(key)
        table = cipher.get_table()

        self.table_text.config(state='normal')
        self.table_text.delete(1.0, tk.END)
        self.table_text.insert(1.0, table)
        self.table_text.config(state='disabled')

        standard = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЫЬЭЮЯ_"
        messagebox.showinfo("Таблица замены",
                            f"Стандартный алфавит:\n{standard}\n\n"
                            f"Таблица по ключу '{key}':\n{table}")

    def encrypt_text(self):
        """Зашифровать текст простым шифром"""
        key = self.key_entry.get().strip().upper()
        text = self.text_encrypt.get("1.0", tk.END).strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if not text:
            messagebox.showerror("Ошибка", "Введите текст для шифрования")
            return

        cipher = TrithemusCipher(key)
        encrypted = cipher.encrypt(text)

        self.result_encrypt.delete("1.0", tk.END)
        self.result_encrypt.insert("1.0", encrypted)

    def decrypt_text(self):
        """Расшифровать текст простым шифром"""
        key = self.key_entry.get().strip().upper()
        cipher_text = self.text_decrypt.get("1.0", tk.END).strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if not cipher_text:
            messagebox.showerror("Ошибка", "Введите шифр для расшифровки")
            return

        cipher = TrithemusCipher(key)
        decrypted = cipher.decrypt(cipher_text)

        self.result_decrypt.delete("1.0", tk.END)
        self.result_decrypt.insert("1.0", decrypted)

    def copy_cipher(self):
        """Копировать результат шифрования в буфер"""
        cipher = self.result_encrypt.get("1.0", tk.END).strip()
        if cipher:
            self.root.clipboard_clear()
            self.root.clipboard_append(cipher)
            messagebox.showinfo("Скопировано", "Шифр скопирован в буфер обмена")

    def paste_cipher(self):
        """Вставить текст из буфера в поле дешифрования"""
        try:
            clipboard_text = self.root.clipboard_get()
            self.text_decrypt.delete("1.0", tk.END)
            self.text_decrypt.insert("1.0", clipboard_text)
        except:
            messagebox.showwarning("Ошибка", "Не удалось получить текст из буфера")

    # ========== ВКЛАДКА 2: ПОЛИАЛФАВИТНЫЙ ШИФР ТРИТЕМУСА ==========

    def setup_poly_tab(self):
        """Настройка вкладки полиалфавитного шифра Тритемуса"""
        # Область для ключа
        frame_key = ttk.LabelFrame(self.frame_poly, text="Ключ", padding=10)
        frame_key.pack(fill='x', padx=10, pady=(10, 5))

        ttk.Label(frame_key, text="Ключ (текст):").grid(row=0, column=0, sticky='w', pady=5)
        self.poly_key_entry = ttk.Entry(frame_key, width=60)
        self.poly_key_entry.grid(row=0, column=1, padx=5, pady=5)

        # Область шифрования
        frame_encrypt = ttk.LabelFrame(self.frame_poly, text="Шифрование", padding=10)
        frame_encrypt.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_encrypt, text="Текст для шифрования:").grid(row=0, column=0, sticky='w', pady=5)
        self.poly_text_encrypt = scrolledtext.ScrolledText(frame_encrypt, height=5, width=70)
        self.poly_text_encrypt.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame_encrypt, text="Зашифровать", command=self.poly_encrypt_text).grid(row=1, column=1, pady=10,
                                                                                           sticky='w')

        ttk.Label(frame_encrypt, text="Результат:").grid(row=2, column=0, sticky='w', pady=5)
        self.poly_result_encrypt = scrolledtext.ScrolledText(frame_encrypt, height=5, width=70)
        self.poly_result_encrypt.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(frame_encrypt, text="Копировать шифр", command=self.poly_copy_cipher).grid(row=3, column=1, pady=5,
                                                                                              sticky='w')

        # Область дешифрования
        frame_decrypt = ttk.LabelFrame(self.frame_poly, text="Дешифрование", padding=10)
        frame_decrypt.pack(fill='x', padx=10, pady=(5, 10))

        ttk.Label(frame_decrypt, text="Шифр для расшифровки:").grid(row=0, column=0, sticky='w', pady=5)
        self.poly_text_decrypt = scrolledtext.ScrolledText(frame_decrypt, height=5, width=70)
        self.poly_text_decrypt.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame_decrypt, text="Вставить из буфера", command=self.poly_paste_cipher).grid(row=1, column=1,
                                                                                                  pady=5, sticky='w')
        ttk.Button(frame_decrypt, text="Расшифровать", command=self.poly_decrypt_text).grid(row=2, column=1, pady=10,
                                                                                            sticky='w')

        ttk.Label(frame_decrypt, text="Результат:").grid(row=3, column=0, sticky='w', pady=5)
        self.poly_result_decrypt = scrolledtext.ScrolledText(frame_decrypt, height=5, width=70)
        self.poly_result_decrypt.grid(row=3, column=1, padx=5, pady=5)

    # Методы для полиалфавитного шифра
    def poly_encrypt_text(self):
        """Зашифровать текст полиалфавитным шифром"""
        key = self.poly_key_entry.get().strip().upper()
        text = self.poly_text_encrypt.get("1.0", tk.END).strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if not text:
            messagebox.showerror("Ошибка", "Введите текст для шифрования")
            return

        try:
            cipher = PolyalphabeticTrithemus(key)
            encrypted = cipher.encrypt(text)

            self.poly_result_encrypt.delete("1.0", tk.END)
            self.poly_result_encrypt.insert("1.0", encrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шифрования: {str(e)}")

    def poly_decrypt_text(self):
        """Расшифровать текст полиалфавитным шифром"""
        key = self.poly_key_entry.get().strip().upper()
        cipher_text = self.poly_text_decrypt.get("1.0", tk.END).strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if not cipher_text:
            messagebox.showerror("Ошибка", "Введите шифр для расшифровки")
            return

        try:
            cipher = PolyalphabeticTrithemus(key)
            decrypted = cipher.decrypt(cipher_text)

            self.poly_result_decrypt.delete("1.0", tk.END)
            self.poly_result_decrypt.insert("1.0", decrypted)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка дешифрования: {str(e)}")

    def poly_copy_cipher(self):
        """Копировать результат полиалфавитного шифрования"""
        cipher = self.poly_result_encrypt.get("1.0", tk.END).strip()
        if cipher:
            self.root.clipboard_clear()
            self.root.clipboard_append(cipher)
            messagebox.showinfo("Скопировано", "Шифр скопирован в буфер обмена")

    def poly_paste_cipher(self):
        """Вставить текст из буфера в поле дешифрования"""
        try:
            clipboard_text = self.root.clipboard_get()
            self.poly_text_decrypt.delete("1.0", tk.END)
            self.poly_text_decrypt.insert("1.0", clipboard_text)
        except:
            messagebox.showwarning("Ошибка", "Не удалось получить текст из буфера")

    # ========== ВКЛАДКА 3: S-БЛОКИ ==========

    def setup_sblock_tab(self):
        """Настройка вкладки S-блоков"""
        # Информационная панель
        frame_info = ttk.LabelFrame(self.frame_sblock, text="Информация", padding=10)
        frame_info.pack(fill='x', padx=10, pady=(10, 5))

        info_text = "S-блоки используют полиалфавитный шифр с фиксированными размерами:\n" \
                    "• Размер блока: 4 символа\n" \
                    "• Длина ключа: 16 символов"

        ttk.Label(frame_info, text=info_text, wraplength=800, justify='left').pack(padx=5, pady=5)

        # Область для ключа
        frame_key = ttk.LabelFrame(self.frame_sblock, text="Ключ", padding=10)
        frame_key.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_key, text="Ключ (16 символов):").grid(row=0, column=0, sticky='w', pady=5)
        self.sblock_key_entry = ttk.Entry(frame_key, width=50)
        self.sblock_key_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_key, text="Длина:").grid(row=0, column=2, padx=5, pady=5)
        self.sblock_key_len_label = ttk.Label(frame_key, text="0", width=5)
        self.sblock_key_len_label.grid(row=0, column=3, padx=5, pady=5)

        # Обновляем длину при вводе
        self.sblock_key_entry.bind('<KeyRelease>', self.update_sblock_key_len)

        # Область для тестового блока
        frame_test = ttk.LabelFrame(self.frame_sblock, text="Тестирование блока", padding=10)
        frame_test.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_test, text="Блок (4 символа):").grid(row=0, column=0, sticky='w', pady=5)
        self.sblock_test_entry = ttk.Entry(frame_test, width=20)
        self.sblock_test_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame_test, text="Зашифровать блок", command=self.sblock_encrypt_test).grid(row=0, column=2, padx=10)
        ttk.Button(frame_test, text="Расшифровать блок", command=self.sblock_decrypt_test).grid(row=0, column=3, padx=5)

        ttk.Label(frame_test, text="Результат:").grid(row=1, column=0, sticky='w', pady=5)
        self.sblock_test_result = ttk.Entry(frame_test, width=20, state='readonly')
        self.sblock_test_result.grid(row=1, column=1, padx=5, pady=5)

    # Методы для S-блоков
    def update_sblock_key_len(self, event=None):
        """Обновить отображение длины ключа"""
        key = self.sblock_key_entry.get()
        self.sblock_key_len_label.config(text=str(len(key)))

    def sblock_encrypt_test(self):
        """Шифрование блока"""
        key = self.sblock_key_entry.get().strip().upper()
        block = self.sblock_test_entry.get().strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if len(key) != 16:
            messagebox.showerror("Ошибка", "Длина ключа должна быть 16 символов")
            return
        if not block:
            messagebox.showerror("Ошибка", "Введите блок для шифрования")
            return
        if len(block) != 4:
            messagebox.showerror("Ошибка", "Длина блока должна быть 4 символа")
            return

        result = STrithemus.encrypt_block(block, key)
        self.sblock_test_result.config(state='normal')
        self.sblock_test_result.delete(0, tk.END)
        self.sblock_test_result.insert(0, result)
        self.sblock_test_result.config(state='readonly')

    def sblock_decrypt_test(self):
        """Дешифрование блока"""
        key = self.sblock_key_entry.get().strip().upper()
        block = self.sblock_test_entry.get().strip().upper()

        if not key:
            messagebox.showerror("Ошибка", "Введите ключ")
            return
        if len(key) != 16:
            messagebox.showerror("Ошибка", "Длина ключа должна быть 16 символов")
            return
        if not block:
            messagebox.showerror("Ошибка", "Введите блок для дешифрования")
            return
        if len(block) != 4:
            messagebox.showerror("Ошибка", "Длина блока должна быть 4 символа")
            return

        result = STrithemus.decrypt_block(block, key)
        self.sblock_test_result.config(state='normal')
        self.sblock_test_result.delete(0, tk.END)
        self.sblock_test_result.insert(0, result)
        self.sblock_test_result.config(state='readonly')

    # ========== ВКЛАДКА 4: УСИЛЕННЫЕ S-БЛОКИ ==========

    def setup_enhanced_tab(self):
        """Настройка вкладки усиленных S-блоков"""
        # Информационная панель
        frame_info = ttk.LabelFrame(self.frame_enhanced, text="Информация", padding=10)
        frame_info.pack(fill='x', padx=10, pady=(10, 5))

        info_text = "Усиленные (модифицированные) S-блоки:\n" \
                    "• Размер блока: 4 символа\n" \
                    "• Длина ключа: 16 символов"

        ttk.Label(frame_info, text=info_text, wraplength=900, justify='left').pack(padx=5, pady=5)

        # Область для ключа
        frame_key = ttk.LabelFrame(self.frame_enhanced, text="Ключ", padding=10)
        frame_key.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_key, text="Ключ (16 символов):").grid(row=0, column=0, sticky='w', pady=5)
        self.enhanced_key_entry = ttk.Entry(frame_key, width=50)
        self.enhanced_key_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_key, text="Длина:").grid(row=0, column=2, padx=5, pady=5)
        self.enhanced_key_len_label = ttk.Label(frame_key, text="16", width=5)
        self.enhanced_key_len_label.grid(row=0, column=3, padx=5, pady=5)

        # Обновляем длину при вводе
        self.enhanced_key_entry.bind('<KeyRelease>', self.update_enhanced_key_len)

        # Область для работы с блоком
        frame_block = ttk.LabelFrame(self.frame_enhanced, text="Работа с блоком", padding=10)
        frame_block.pack(fill='x', padx=10, pady=5)

        ttk.Label(frame_block, text="Блок (4 символа):").grid(row=0, column=0, sticky='w', pady=5)
        self.enhanced_block_entry = ttk.Entry(frame_block, width=20)
        self.enhanced_block_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame_block, text="Зашифровать",
                   command=self.enhanced_encrypt_block).grid(row=0, column=2, padx=10)
        ttk.Button(frame_block, text="Расшифровать",
                   command=self.enhanced_decrypt_block).grid(row=0, column=3, padx=5)

        ttk.Label(frame_block, text="Результат:").grid(row=1, column=0, sticky='w', pady=5)
        self.enhanced_block_result = ttk.Entry(frame_block, width=20)
        self.enhanced_block_result.grid(row=1, column=1, padx=5, pady=5)

        # Методы для усиленных S-блоков

    def update_enhanced_key_len(self, event=None):
        """Обновить отображение длины ключа"""
        key = self.enhanced_key_entry.get()
        self.enhanced_key_len_label.config(text=str(len(key)))

    def enhanced_encrypt_block(self):
        """Усиленное шифрование блока"""
        key = self.enhanced_key_entry.get().strip().upper()
        block = self.enhanced_block_entry.get().strip().upper()

        if not key or len(key) != 16 or not block or len(block) != 4:
            messagebox.showerror("Ошибка", "Ключ должен быть 16 символов, блок - 4 символа")
            return

        result = EnhancedSTrithemus.encrypt_block(block, key)
        self.enhanced_block_result.delete(0, tk.END)
        self.enhanced_block_result.insert(0, result)

    def enhanced_decrypt_block(self):
        """Усиленное дешифрование блока"""
        key = self.enhanced_key_entry.get().strip().upper()
        block = self.enhanced_block_entry.get().strip().upper()

        if not key or len(key) != 16 or not block or len(block) != 4:
            messagebox.showerror("Ошибка", "Ключ должен быть 16 символов, блок - 4 символа")
            return

        result = EnhancedSTrithemus.decrypt_block(block, key)
        self.enhanced_block_result.delete(0, tk.END)
        self.enhanced_block_result.insert(0, result)


def main():
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()