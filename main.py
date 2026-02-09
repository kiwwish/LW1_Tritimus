import sys
import os

# Добавляем папку src в путь поиска модулей
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_dir)

try:
    from gui import main

    if __name__ == "__main__":
        main()
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print("Убедитесь, что папка 'src' существует и содержит:")
    print("  alphabet.py, trithemus.py, gui.py")
    input("Нажмите Enter для выхода...")