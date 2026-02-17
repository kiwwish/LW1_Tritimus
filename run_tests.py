#!/usr/bin/env python3
import sys
import os

src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_dir)

required_modules = ['alphabet', 'polyTritimus']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print("ОШИБКА: Не найдены следующие модули:")
    for module in missing_modules:
        print(f"   - {module}.py")
    print(f"\nПапка src: {src_dir}")
    if os.path.exists(src_dir):
        print("Содержимое папки src:")
        for file in os.listdir(src_dir):
            if file.endswith('.py'):
                print(f"   - {file}")
    else:
        print(f"Папка {src_dir} не найдена!")
    sys.exit(1)

try:
    from src.test_sblocks import main

    if __name__ == "__main__":
        print("=" * 80)
        print("ТЕСТИРОВАНИЕ S-БЛОКОВ")
        print("=" * 80)
        print("Доступные режимы:")
        print("  • Обычные S-блоки:    python run_tests.py")
        print("  • Усиленные S-блоки:  python run_tests.py --enhanced")
        print("  • Фиксированный seed: python run_tests.py --seed 42")
        print("=" * 80)
        print()

        main()

except ImportError as e:
    print(f"Ошибка импорта test_sblocks: {e}")
    input("Нажмите Enter для выхода...")