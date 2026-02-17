import random
from collections import Counter
from alphabet import sym2num, num2sym, ALPHABET_SIZE, verify_alphabet
from polyTritimus import STrithemus, EnhancedSTrithemus

class SBlockTester:
    """Тестирование S-блоков строго по двум требованиям преподавателя"""

    def __init__(self, use_enhanced=False):
        self.use_enhanced = use_enhanced
        self.alphabet_size = ALPHABET_SIZE
        verify_alphabet()

    def generate_random_block(self):
        return ''.join(num2sym(random.randint(0, self.alphabet_size - 1)) for _ in range(4))

    def generate_random_key(self):
        return ''.join(num2sym(random.randint(0, self.alphabet_size - 1)) for _ in range(16))

    def encrypt_block(self, block, key):
        if self.use_enhanced:
            return EnhancedSTrithemus.encrypt_block(block, key)
        else:
            return STrithemus.encrypt_block(block, key)

    def hamming_distance(self, str1, str2):
        return sum(a != b for a, b in zip(str1, str2))

    def are_same_multiset(self, str1, str2):
        return sorted(str1) == sorted(str2)

    def modify_one_char(self, block):
        block_list = list(block)
        pos = random.randint(0, 3)
        num = sym2num(block_list[pos])
        new_num = (num + 1) % self.alphabet_size
        block_list[pos] = num2sym(new_num)
        return ''.join(block_list)

    def rotate_block(self, block):
        shift = random.randint(1, 3)
        return block[shift:] + block[:shift]

    def run_tests(self, num_blocks=30, num_keys=20, seed=None):
        if seed is not None:
            random.seed(seed)
            print(f"Seed для воспроизводимости: {seed}")

        blocks = [self.generate_random_block() for _ in range(num_blocks)]
        keys = [self.generate_random_key() for _ in range(num_keys)]

        print("\nСгенерированные входные блоки (30 шт):")
        for idx, block in enumerate(blocks, 1):
            print(f"{idx:2d}: {block}")

        print("\nСгенерированные ключи (20 шт):")
        for idx, key in enumerate(keys, 1):
            print(f"{idx:2d}: {key}")

        print(f"\nТЕСТИРОВАНИЕ {'УСИЛЕННЫХ' if self.use_enhanced else 'ОБЫЧНЫХ'} S-БЛОКОВ")
        print(f"Блоков: {num_blocks}, Ключей: {num_keys}, всего комбинаций: {num_blocks * num_keys}\n")


        # ───────────────────────────────────────────────
        # ТЕСТ 1: малое изменение входа
        # ───────────────────────────────────────────────
        print("=" * 80)
        print("ТЕСТ 1: МАЛОЕ ИЗМЕНЕНИЕ ВХОДА (один символ → соседний)")
        print("=" * 80)

        full1 = partial1 = failed1 = 0
        examples1 = []
        weak_blocks1 = Counter()
        weak_keys1 = Counter()

        for i, block in enumerate(blocks):
            for j, key in enumerate(keys):
                mod_block = self.modify_one_char(block)
                c1 = self.encrypt_block(block, key)
                c2 = self.encrypt_block(mod_block, key)

                if c1 == "input_error" or c2 == "input_error":
                    continue

                dist = self.hamming_distance(c1, c2)

                if dist >= 3:
                    full1 += 1
                elif dist == 2:
                    partial1 += 1
                    weak_blocks1[block] += 1
                    weak_keys1[key] += 1
                else:
                    failed1 += 1
                    weak_blocks1[block] += 1
                    weak_keys1[key] += 1

                # Сохраняем первые 10 примеров
                if len(examples1) < 10:
                    examples1.append((block, mod_block, key[:8]+"...", c1, c2, dist))

        total1 = full1 + partial1 + failed1
        print(f"Полностью пройдено (разница ≥3): {full1}/{total1} ({full1/total1*100:.1f}%)")
        print(f"Частично пройдено (разница =2): {partial1}/{total1} ({partial1/total1*100:.1f}%)")
        print(f"Завалено (разница ≤1): {failed1}/{total1} ({failed1/total1*100:.1f}%)")
        if examples1:
            print("\nПримеры (первые 10):")
            print(f"{'Исх':<6} {'Изм':<6} {'Ключ':<12} {'C1':<6} {'C2':<6} {'Δ'}")
            print("-" * 45)
            for ex in examples1:
                print(f"{ex[0]:<6} {ex[1]:<6} {ex[2]:<12} {ex[3]:<6} {ex[4]:<6} {ex[5]}")

        if weak_blocks1:
            print("\nТоп слабых входов:", weak_blocks1.most_common(5))
        if weak_keys1:
            print("Топ слабых ключей:", weak_keys1.most_common(5))

            # ───────────────────────────────────────────────
            # ТЕСТ 2: ротация входа
            # ───────────────────────────────────────────────
        print("\n" + "=" * 80)
        print("ТЕСТ 2: РОТАЦИЯ ВХОДА (выходы не должны иметь одинаковый набор символов)")
        print("=" * 80)

        full2 = partial2 = failed2 = 0
        examples2 = []
        weak_blocks2 = Counter()
        weak_keys2 = Counter()

        for i, block in enumerate(blocks):
            for j, key in enumerate(keys):
                rot_block = self.rotate_block(block)
                c1 = self.encrypt_block(block, key)
                c2 = self.encrypt_block(rot_block, key)

                if c1 == "input_error" or c2 == "input_error":
                    continue

                same_multiset = self.are_same_multiset(c1, c2)
                dist = self.hamming_distance(c1, c2)

                if not same_multiset and dist >= 3:
                    full2 += 1
                elif not same_multiset and dist == 2:
                    partial2 += 1
                    weak_blocks2[block] += 1
                    weak_keys2[key] += 1
                else:
                    failed2 += 1
                    weak_blocks2[block] += 1
                    weak_keys2[key] += 1

                if len(examples2) < 10:
                    examples2.append((block, rot_block, key[:8] + "...", c1, c2, "нет" if not same_multiset else "да"))

        total2 = full2 + partial2 + failed2
        print(f"Полностью пройдено (разные наборы + Δ≥3): {full2}/{total2} ({full2 / total2 * 100:.1f}%)")
        print(f"Частично пройдено (разные наборы + Δ=2): {partial2}/{total2} ({partial2 / total2 * 100:.1f}%)")
        print(f"Завалено (одинаковые наборы): {failed2}/{total2} ({failed2 / total2 * 100:.1f}%)")

        if examples2:
            print("\nПримеры (первые 10):")
            print(f"{'Исх':<6} {'Рот':<6} {'Ключ':<12} {'C1':<6} {'C2':<6} {'Одинаковый набор?'}")
            print("-" * 60)
            for ex in examples2:
                print(f"{ex[0]:<6} {ex[1]:<6} {ex[2]:<12} {ex[3]:<6} {ex[4]:<6} {ex[5]}")

        if weak_blocks2:
            print("\nТоп слабых входов:", weak_blocks2.most_common(5))
        if weak_keys2:
            print("Топ слабых ключей:", weak_keys2.most_common(5))

        # ───────────────────────────────────────────────
        # Итоговый вывод (как в методичке)
        # ───────────────────────────────────────────────
        print("\n" + "=" * 80)
        print("ИТОГОВАЯ ОЦЕНКА")
        print("=" * 80)
        print("Хороший S-блок должен проходить все тесты полностью, быть вычислительно простым.")
        print("Наши не такие.")
        if self.use_enhanced:
            if full1 / total1 > 0.85 and full2 / total2 > 0.90:
                print("Усиленный вариант показывает приемлемую чувствительность.")
            else:
                print("Даже усиленный вариант имеет слабые места (много частично пройденных или заваленных).")
        else:
            print("Обычный вариант демонстрирует крайне слабую реакцию на изменения входа.")
            print("Рекомендация: использовать усиленную модификацию.")

        print("\n" + "=" * 80)

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Тестирование S-блоков (только 2 теста по требованиям преподавателя)')
    parser.add_argument('--enhanced', action='store_true', help='Тестировать усиленные S-блоки')
    parser.add_argument('--seed', type=int, default=None, help='Seed для воспроизводимости')
    args = parser.parse_args()
    tester = SBlockTester(use_enhanced=args.enhanced)
    tester.run_tests(seed=args.seed)

if __name__ == "__main__":
    main()