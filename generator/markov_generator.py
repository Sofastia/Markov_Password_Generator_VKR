

import random
import secrets
import hashlib
import json
import gc
from collections import defaultdict
from cryptography.fernet import Fernet

class SecurityError(Exception): pass

class MarkovMnemonicPasswordGenerator:
    """
    Класс для генерации мнемонических паролей на основе цепей Маркова.
    Включает функции обучения, генерации квази-слов, пост-обработки
    и безопасного хранения модели.
    """
    def __init__(self, order=2):
        self.order = order
        self.model = defaultdict(lambda: defaultdict(int))
        self.starters = []
        self.overall_word_counts = defaultdict(int) 
        self.max_overall_freq = 1 

    def _preprocess_text(self, text):
        """Очистка текста от знаков препинания и приведение к нижнему регистру."""
        text = text.lower()
        for char in '.,;:"\'!?-—()[]{}/\\':
            text = text.replace(char, ' ')
        words = text.split()
        return words

    def train(self, text_corpus):
        """Обучение модели на заданном корпусе."""
        self.model.clear()
        self.starters.clear()
        self.overall_word_counts.clear()
        self.max_overall_freq = 1

        words = self._preprocess_text(text_corpus)
        if len(words) < self.order + 1:
            raise ValueError(f"Корпус содержит {len(words)} слов, что слишком мало для выбранного порядка цепи Маркова ({self.order}).")

        # Подсчет общей частоты слов
        for word in words:
            self.overall_word_counts[word] += 1
        if self.overall_word_counts:
            self.max_overall_freq = max(self.overall_word_counts.values())

        # Построение матрицы переходов
        for i in range(len(words) - self.order):
            if self.order == 1:
                current_state = words[i]
                next_word = words[i+1]
            else:
                current_state = tuple(words[i:i+self.order])
                next_word = words[i+self.order]

            self.model[current_state][next_word] += 1
            
            # Определение стартовых состояний (начало предложения)
            if i == 0 or words[i-1] in ['.', '!', '?']:
                 self.starters.append(current_state)
        
        if not self.starters and self.model:
            self.starters = list(self.model.keys())

    def save_model_secure(self, filepath, key):
        """Шифрование матрицы переходов (AES) + Контроль целостности (SHA-256)."""
        model_data = {str(k): dict(v) for k, v in self.model.items()}
        export_bundle = {
            "order": self.order,
            "model": model_data,
            "starters": [str(s) for s in self.starters],
            "word_counts": dict(self.overall_word_counts),
            "max_freq": self.max_overall_freq
        }
        
        raw_bytes = json.dumps(export_bundle).encode('utf-8')
        f = Fernet(key)
        encrypted_data = f.encrypt(raw_bytes)
        
        # Хеш для проверки целостности
        checksum = hashlib.sha256(encrypted_data).hexdigest()
        
        with open(filepath, 'wb') as f_out:
            f_out.write(encrypted_data)
        with open(filepath + ".sha256", 'w') as f_hash:
            f_hash.write(checksum)

    def load_model_secure(self, filepath, key):
        """Загрузка зашифрованной модели с проверкой целостности."""
        with open(filepath, 'rb') as f_in:
            encrypted_data = f_in.read()
            
        with open(filepath + ".sha256", 'r') as f_hash:
            stored_hash = f_hash.read()

        if hashlib.sha256(encrypted_data).hexdigest() != stored_hash:
            raise SecurityError("Целостность данных нарушена! Модель была изменена.")

        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        data = json.loads(decrypted_data.decode('utf-8'))
        
        self.order = data['order']
        self.max_overall_freq = data['max_freq']
        self.overall_word_counts = defaultdict(int, data['word_counts'])
        
        # Восстановление модели (сложный процесс парсинга ключей из строк)
        self.model.clear()
        for k, v in data['model'].items():
            if self.order == 1:
                 new_key = k
            else:
                 # Парсинг строки обратно в кортеж
                 k_parts = k.strip("()").replace("'", "").replace(" ", "").split(",")
                 new_key = tuple(k_parts)
                 
            self.model[new_key] = defaultdict(int, v)
            
        # Восстановление стартеров
        self.starters = []
        for s in data['starters']:
            if self.order == 1:
                self.starters.append(s)
            else:
                s_parts = s.strip("()").replace("'", "").replace(" ", "").split(",")
                self.starters.append(tuple(s_parts))


    def secure_clear_memory(self):
        """Безопасная очистка матриц из RAM."""
        self.model.clear()
        self.starters.clear()
        gc.collect()

    def _get_next_word(self, current_state, rarity_weight_factor=0.0):
        """Выбор следующего слова с учетом фактора редкости (rarity_weight_factor)."""
        if current_state not in self.model or not self.model[current_state]:
            return None

        possible_next_words_counts = self.model[current_state]
        words = list(possible_next_words_counts.keys())
        
        adjusted_weights = []
        for word in words:
            original_weight = possible_next_words_counts[word]
            overall_freq = self.overall_word_counts.get(word, 1)
            rarity_score = (self.max_overall_freq - overall_freq + 1)
            
            # Взвешивание: чем реже слово, тем выше его скор при rarity_weight_factor > 0
            adjusted_weight = original_weight * (rarity_score ** rarity_weight_factor)
            adjusted_weights.append(adjusted_weight)
            
        if sum(adjusted_weights) == 0:
            # Fallback к оригинальным весам, если все скоры обнулились (крайне маловероятно)
            adjusted_weights = list(possible_next_words_counts.values())

        # Использование random.choices (взвешенный случайный выбор)
        return random.choices(words, weights=adjusted_weights, k=1)[0]


    def _generate_mnemonic_phrase(self, num_words, rarity_weight_factor):
        """Генерирует последовательность слов (квази-фразу)."""
        if not self.starters or not self.model:
            raise ValueError("Модель не обучена или корпус слишком мал для обучения.")
        
        current_state = random.choice(self.starters)
        
        # Обработка случая, когда стартер - слово, но модель order=2
        if self.order == 2 and not isinstance(current_state, tuple):
             matching_states = [s for s in self.model if isinstance(s, tuple) and s[0] == current_state]
             if matching_states:
                 current_state = random.choice(matching_states)
             else:
                 current_state = random.choice(list(self.model.keys()))

        phrase = list(current_state) if self.order > 1 else [current_state]
        
        if num_words < self.order:
            phrase = phrase[:num_words]
            return ' '.join(phrase)

        while len(phrase) < num_words:
            next_word = self._get_next_word(current_state, rarity_weight_factor)
            if next_word is None:
                break 
            
            phrase.append(next_word)
            
            if self.order == 1:
                current_state = next_word
            else:
                current_state = tuple(phrase[-self.order:])
        
        return ' '.join(phrase)

    def generate_password(self, num_words=4, min_length=12, max_length=32,
                          first_cap_prob=0.8,
                          random_char_count=3,
                          random_case_prob=0.2,
                          leet_speak_prob=0.0,
                          rarity_weight_factor=0.0):
        """Генерирует финальный пароль, включая пост-обработку."""
        
        phrase = self._generate_mnemonic_phrase(num_words, rarity_weight_factor)
        
        if not phrase.strip():
            raise ValueError("Не удалось сгенерировать осмысленную фразу.")

        password_chars = []
        
        # 1. Пост-обработка слов (регистр, Leet Speak)
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 'l': '1', 'z': '2', 't': '7'}
        
        for word in phrase.split():
            if not word: continue
            
            # Первая буква (Cap)
            if random.random() < first_cap_prob:
                password_chars.append(word[0].upper())
            else:
                password_chars.append(word[0])
            
            # Остальные буквы
            for char in word[1:]:
                processed_char = char
                
                # Leet Speak
                if random.random() < leet_speak_prob and char.lower() in leet_map:
                    processed_char = leet_map[char.lower()]
                # Случайный регистр
                elif random.random() < random_case_prob and char.isalpha():
                    processed_char = char.upper() if random.random() < 0.5 else char.lower()
                
                password_chars.append(processed_char)
            
            password_chars.append(' ') # Разделитель между словами

        if password_chars and password_chars[-1] == ' ':
            password_chars.pop()

        # 2. Инъекция случайных символов/цифр
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for _ in range(random_char_count):
            char_type_choice = random.randint(0, 2)
            
            if char_type_choice == 0:
                char_to_add = str(random.randint(0, 9))
            elif char_type_choice == 1:
                char_to_add = random.choice(symbols)
            else:
                char_to_add = random.choice('abcdefghijklmnopqrstuvwxyz').upper()

            insert_pos = random.randint(0, len(password_chars))
            password_chars.insert(insert_pos, char_to_add)
        
        final_password = "".join(password_chars)
        
        # 3. Добавление символов до минимальной длины
        while len(final_password) < min_length:
            char_type = random.randint(0, 2)
            if char_type == 0:
                final_password += str(random.randint(0, 9))
            elif char_type == 1:
                final_password += random.choice(symbols)
            else:
                final_password += random.choice('abcdefghijklmnopqrstuvwxyz').upper()

        # 4. Контроль максимальной длины
        if len(final_password) > max_length:
            final_password = final_password[:max_length]

        return final_password
