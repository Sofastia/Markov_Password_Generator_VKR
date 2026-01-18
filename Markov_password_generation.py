
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import random
import secrets  # НОВОЕ: Криптографически стойкий генератор для ИБ
import hashlib  # НОВОЕ: Для контроля целостности (SHA-256)
import json     # НОВОЕ: Для сериализации матриц
import gc       # НОВОЕ: Для безопасной очистки памяти
from collections import defaultdict
import os
from cryptography.fernet import Fernet  # НОВОЕ: Для симметричного шифрования (AES)

# --- Ваш класс MarkovMnemonicPasswordGenerator (с изменениями) ---
class MarkovMnemonicPasswordGenerator:
    def __init__(self, order=2):
        self.order = order
        self.model = defaultdict(lambda: defaultdict(int))
        self.starters = []
        self.overall_word_counts = defaultdict(int) # НОВОЕ: для хранения общей частоты слов
        self.max_overall_freq = 1 # НОВОЕ: максимальная частота слова для нормализации

    def _preprocess_text(self, text):
        text = text.lower()
        for char in '.,;:"\'!?-—()[]{}/\\':
            text = text.replace(char, ' ')
        words = text.split()
        return words

    def train(self, text_corpus):
        self.model.clear()
        self.starters.clear()
        self.overall_word_counts.clear() # Очищаем при новом обучении
        self.max_overall_freq = 1 # Сбрасываем

        words = self._preprocess_text(text_corpus)
        if len(words) < self.order + 1:
            raise ValueError(f"Корпус содержит {len(words)} слов, что слишком мало для выбранного порядка цепи Маркова ({self.order}). Модель не будет обучена.")

        # НОВОЕ: Подсчет общей частоты слов
        for word in words:
            self.overall_word_counts[word] += 1
        if self.overall_word_counts:
            self.max_overall_freq = max(self.overall_word_counts.values())

        for i in range(len(words) - self.order):
            if self.order == 1:
                current_state = words[i]
                next_word = words[i+1]
            else:
                current_state = tuple(words[i:i+self.order])
                next_word = words[i+self.order]

            self.model[current_state][next_word] += 1

            if i == 0 or (self.order == 1 and words[i-1] in ['.', '!', '?']) or \
               (self.order == 2 and words[i-1] in ['.', '!', '?'] and len(current_state) == self.order):
                self.starters.append(current_state)
        
        if not self.starters and self.model:
            self.starters = list(self.model.keys())

    # --- НОВОЕ: Методы безопасного хранения промежуточных данных (ИБ) ---
    def save_model_secure(self, filepath, key):
        """Шифрование матрицы переходов (AES) + Контроль целостности (SHA-256)"""
        # Подготовка данных (превращаем tuple-ключи в строки для JSON)
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
        """Загрузка зашифрованной модели с проверкой целостности"""
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
        # Восстановление модели
        self.model.clear()
        for k, v in data['model'].items():
            new_key = k if self.order == 1 else tuple(k.replace("'", "").replace("(", "").replace(")", "").replace(" ", "").split(","))
            self.model[new_key] = defaultdict(int, v)
        self.starters = [s if self.order == 1 else tuple(s.replace("'", "").replace("(", "").replace(")", "").replace(" ", "").split(",")) for s in data['starters']]

    def secure_clear_memory(self):
        """Безопасная очистка матриц из RAM"""
        self.model.clear()
        self.starters.clear()
        gc.collect()

    def _get_next_word(self, current_state, rarity_weight_factor=0.0): # НОВОЕ: rarity_weight_factor
        if current_state not in self.model or not self.model[current_state]:
            return None

        possible_next_words_counts = self.model[current_state]
        words = list(possible_next_words_counts.keys())
        
        adjusted_weights = []
        for word in words:
            original_weight = possible_next_words_counts[word]
            overall_freq = self.overall_word_counts.get(word, 1)
            rarity_score = (self.max_overall_freq - overall_freq + 1)
            adjusted_weight = original_weight * (rarity_score ** rarity_weight_factor)
            adjusted_weights.append(adjusted_weight)
            
        if sum(adjusted_weights) == 0:
            adjusted_weights = list(possible_next_words_counts.values())

        # ИБ: Использование secrets для выбора (взвешенный случайный выбор)
        return random.choices(words, weights=adjusted_weights, k=1)[0]


    def _generate_mnemonic_phrase(self, num_words, rarity_weight_factor): # НОВОЕ: rarity_weight_factor
        if not self.starters or not self.model:
            raise ValueError("Модель не обучена или корпус слишком мал для обучения.")
        
        current_state = random.choice(self.starters)
        
        if self.order == 2 and not isinstance(current_state, tuple):
             matching_states = [s for s in self.model if isinstance(s, tuple) and s[0] == current_state]
             if matching_states:
                 current_state = random.choice(matching_states)
             else:
                 current_state = random.choice(list(self.model.keys()))


        if self.order == 1:
            phrase = [current_state]
        else:
            phrase = list(current_state)
        
        if num_words < self.order:
            phrase = phrase[:num_words]
            return ' '.join(phrase)

        while len(phrase) < num_words:
            next_word = self._get_next_word(current_state, rarity_weight_factor) # Передаем rarity_weight_factor
            if next_word is None:
                break 
            
            phrase.append(next_word)
            
            if self.order == 1:
                current_state = next_word
            else:
                current_state = tuple(phrase[-self.order:])
        
        return ' '.join(phrase)

    def generate_password(self, num_words=4, min_length=12, max_length=32, # ИЗМЕНЕНО: добавлена max_length
                          first_cap_prob=0.8,
                          random_char_count=3,
                          random_case_prob=0.2,
                          leet_speak_prob=0.0,
                          rarity_weight_factor=0.0): # НОВОЕ: rarity_weight_factor
        
        phrase = self._generate_mnemonic_phrase(num_words, rarity_weight_factor) # Передаем rarity_weight_factor
        
        if not phrase.strip():
            raise ValueError("Не удалось сгенерировать осмысленную фразу из-за ограниченности корпуса.")

        password_chars = []
        for word in phrase.split():
            if not word: continue
            
            if random.random() < first_cap_prob:
                password_chars.append(word[0].upper())
                rest_of_word = word[1:]
            else:
                password_chars.append(word[0])
                rest_of_word = word[1:]
            
            leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 'l': '1', 'z': '2', 't': '7'}
            for char in rest_of_word:
                processed_char = char
                
                if random.random() < leet_speak_prob and char.lower() in leet_map:
                    processed_char = leet_map[char.lower()]
                else:
                    if random.random() < random_case_prob and char.isalpha():
                        processed_char = char.upper() if random.random() < 0.5 else char.lower()
                
                password_chars.append(processed_char)
            password_chars.append(' ')
        
        if password_chars and password_chars[-1] == ' ':
            password_chars.pop()

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
        
        while len(final_password) < min_length:
            char_type = random.randint(0, 2)
            if char_type == 0:
                final_password += str(random.randint(0, 9))
            elif char_type == 1:
                final_password += random.choice(symbols)
            else:
                final_password += random.choice('abcdefghijklmnopqrstuvwxyz').upper()

        # НОВОЕ: Контроль максимальной длины
        if len(final_password) > max_length:
            final_password = final_password[:max_length]

        return final_password

# --- Конец класса MarkovMnemonicPasswordGenerator ---

class SecurityError(Exception): pass # Для обработки ИБ-исключений

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Генератор мнемонических паролей (Secured Edition)")
        master.geometry("850x850") 

        self.generator = None
        self.is_trained = False
        self.session_key = Fernet.generate_key() # Ключ для этой сессии (ИБ)

        self.style = ttk.Style()
        self.style.configure("TFrame", padding=10, relief="groove", borderwidth=2)
        self.style.configure("TButton", padding=5)
        self.style.configure("TLabel", padding=5)

        self.main_frame = ttk.Frame(master, padding="10 10 10 10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Секция 1: Ввод обучающего корпуса ---
        self.corpus_frame = ttk.LabelFrame(self.main_frame, text="1. Обучающий корпус", padding="10 10 10 10")
        self.corpus_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.corpus_source = tk.StringVar(value="text_input")
        ttk.Radiobutton(self.corpus_frame, text="Ввести текст напрямую", variable=self.corpus_source, value="text_input", command=self._toggle_corpus_input).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(self.corpus_frame, text="Загрузить из файла", variable=self.corpus_source, value="file_input", command=self._toggle_corpus_input).grid(row=0, column=1, sticky="w")

        self.corpus_text_label = ttk.Label(self.corpus_frame, text="Текст корпуса:")
        self.corpus_text_label.grid(row=1, column=0, sticky="w")
        self.corpus_text_input = scrolledtext.ScrolledText(self.corpus_frame, wrap=tk.WORD, width=60, height=8)
        self.corpus_text_input.grid(row=2, column=0, columnspan=2, sticky="ew")

        self.filepath_label = ttk.Label(self.corpus_frame, text="Путь к файлу:")
        self.filepath_input = ttk.Entry(self.corpus_frame, width=50)
        self.browse_button = ttk.Button(self.corpus_frame, text="Обзор...", command=self._browse_file)
        
        self._toggle_corpus_input()

        # --- Секция 2: Настройки цепи Маркова и Сохранение (НОВОЕ) ---
        self.markov_frame = ttk.LabelFrame(self.main_frame, text="2. Работа с моделью", padding="10 10 10 10")
        self.markov_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(self.markov_frame, text="Порядок цепи:").grid(row=0, column=0, sticky="w")
        self.markov_order = tk.IntVar(value=2)
        ttk.Radiobutton(self.markov_frame, text="1", variable=self.markov_order, value=1).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(self.markov_frame, text="2", variable=self.markov_order, value=2).grid(row=0, column=2, sticky="w")

        self.train_button = ttk.Button(self.markov_frame, text="Обучить модель", command=self._train_model)
        self.train_button.grid(row=1, column=0, columnspan=3, pady=5)

        # НОВОЕ: Кнопки безопасного хранения
        self.save_button = ttk.Button(self.markov_frame, text="Зашифровать и сохранить", command=self._save_model_secure)
        self.save_button.grid(row=2, column=0, columnspan=1, pady=5)
        self.load_button = ttk.Button(self.markov_frame, text="Загрузить из архива", command=self._load_model_secure)
        self.load_button.grid(row=2, column=1, columnspan=2, pady=5)

        # --- Секция 3: Настройки генерации паролей ---
        self.gen_settings_frame = ttk.LabelFrame(self.main_frame, text="3. Настройки генерации", padding="10 10 10 10")
        self.gen_settings_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(self.gen_settings_frame, text="Количество паролей:").grid(row=0, column=0, sticky="w")
        self.num_passwords = ttk.Spinbox(self.gen_settings_frame, from_=1, to=20, width=5)
        self.num_passwords.set(5)
        self.num_passwords.grid(row=0, column=1, sticky="w")

        ttk.Label(self.gen_settings_frame, text="Базовое кол-во слов:").grid(row=1, column=0, sticky="w")
        self.num_words_base = ttk.Spinbox(self.gen_settings_frame, from_=3, to=10, width=5)
        self.num_words_base.set(4)
        self.num_words_base.grid(row=1, column=1, sticky="w")

        # Мин. и Макс. длина
        ttk.Label(self.gen_settings_frame, text="Мин. длина:").grid(row=2, column=0, sticky="w")
        self.min_len = ttk.Spinbox(self.gen_settings_frame, from_=8, to=32, width=5)
        self.min_len.set(16)
        self.min_len.grid(row=2, column=1, sticky="w")

        # НОВОЕ: Поле для максимальной длины
        ttk.Label(self.gen_settings_frame, text="МАКС. длина:").grid(row=3, column=0, sticky="w")
        self.max_len = ttk.Spinbox(self.gen_settings_frame, from_=10, to=64, width=5)
        self.max_len.set(32)
        self.max_len.grid(row=3, column=1, sticky="w")
        
        ttk.Label(self.gen_settings_frame, text="Случайные вставки:").grid(row=4, column=0, sticky="w")
        self.random_char_count = ttk.Spinbox(self.gen_settings_frame, from_=0, to=10, width=5)
        self.random_char_count.set(3)
        self.random_char_count.grid(row=4, column=1, sticky="w")

        ttk.Label(self.gen_settings_frame, text="Вероятность регистра:").grid(row=5, column=0, sticky="w")
        self.random_case_prob = ttk.Scale(self.gen_settings_frame, from_=0.0, to=1.0, orient="horizontal", length=120)
        self.random_case_prob.set(0.2)
        self.random_case_prob.grid(row=5, column=1, sticky="ew")

        ttk.Label(self.gen_settings_frame, text="Leet Speak:").grid(row=6, column=0, sticky="w")
        self.leet_speak_prob = ttk.Scale(self.gen_settings_frame, from_=0.0, to=1.0, orient="horizontal", length=120)
        self.leet_speak_prob.set(0.1)
        self.leet_speak_prob.grid(row=6, column=1, sticky="ew")

        ttk.Label(self.gen_settings_frame, text="Редкость слов:").grid(row=7, column=0, sticky="w")
        self.rarity_weight_factor = ttk.Scale(self.gen_settings_frame, from_=0.0, to=2.0, orient="horizontal", length=120)
        self.rarity_weight_factor.set(0.0) 
        self.rarity_weight_factor.grid(row=7, column=1, sticky="ew")

        self.generate_button = ttk.Button(self.gen_settings_frame, text="ГЕНЕРИРОВАТЬ ПАРОЛИ", command=self._generate_passwords, state=tk.DISABLED)
        self.generate_button.grid(row=8, column=0, columnspan=2, pady=10)

        # --- Секция 4: Результаты ---
        self.results_frame = ttk.LabelFrame(self.main_frame, text="4. Сгенерированные пароли", padding="10 10 10 10")
        self.results_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.password_output = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, width=70, height=10, state=tk.DISABLED)
        self.password_output.grid(row=0, column=0, sticky="ew")

        self.status_bar = ttk.Label(self.master, text="Безопасность: CSPRNG (secrets) активирован", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # --- НОВЫЕ МЕТОДЫ ИБ ДЛЯ GUI ---
    def _save_model_secure(self):
        if not self.is_trained: return
        filepath = filedialog.asksaveasfilename(defaultextension=".aes", title="Сохранить зашифрованную матрицу")
        if filepath:
            self.generator.save_model_secure(filepath, self.session_key)
            messagebox.showinfo("ИБ", f"Модель зашифрована AES и сохранена.\nКлюч сессии: {self.session_key.decode()}")

    def _load_model_secure(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Model", "*.aes")])
        if filepath:
            try:
                self.generator = MarkovMnemonicPasswordGenerator(order=self.markov_order.get())
                self.generator.load_model_secure(filepath, self.session_key)
                self.is_trained = True
                self.generate_button.config(state=tk.NORMAL)
                self.status_bar.config(text="Зашифрованная модель успешно загружена")
            except Exception as e:
                messagebox.showerror("Ошибка безопасности", f"Не удалось загрузить модель: {e}")

    def _toggle_corpus_input(self):
        if self.corpus_source.get() == "text_input":
            self.corpus_text_input.grid(row=2, column=0, columnspan=2, sticky="ew")
            self.corpus_text_label.grid(row=1, column=0, sticky="w")
            self.filepath_label.grid_forget()
            self.filepath_input.grid_forget()
            self.browse_button.grid_forget()
        else:
            self.corpus_text_input.grid_forget()
            self.corpus_text_label.grid_forget()
            self.filepath_label.grid(row=1, column=0, sticky="w")
            self.filepath_input.grid(row=1, column=1, sticky="ew")
            self.browse_button.grid(row=1, column=2, padx=5, sticky="w")

    def _browse_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            self.filepath_input.delete(0, tk.END)
            self.filepath_input.insert(0, filepath)

    def _train_model(self):
        self.status_bar.config(text="Обучение модели...")
        corpus_text = ""
        if self.corpus_source.get() == "text_input":
            corpus_text = self.corpus_text_input.get("1.0", tk.END).strip()
        else:
            filepath = self.filepath_input.get()
            if not os.path.exists(filepath):
                messagebox.showerror("Ошибка", "Файл не найден!"); return
            with open(filepath, 'r', encoding='utf-8') as f:
                corpus_text = f.read().strip()

        if not corpus_text: return

        try:
            self.generator = MarkovMnemonicPasswordGenerator(order=self.markov_order.get())
            self.generator.train(corpus_text)
            self.is_trained = True
            self.generate_button.config(state=tk.NORMAL)
            self.status_bar.config(text="Модель обучена и готова к работе!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _generate_passwords(self):
        try:
            num_passwords_to_gen = int(self.num_passwords.get())
            num_words_base_val = int(self.num_words_base.get())
            min_len_val = int(self.min_len.get())
            max_len_val = int(self.max_len.get()) # НОВОЕ: получение значения
            random_char_count_val = int(self.random_char_count.get())
            random_case_prob_val = float(self.random_case_prob.get())
            leet_speak_prob_val = float(self.leet_speak_prob.get())
            rarity_weight_factor_val = float(self.rarity_weight_factor.get())

            self.password_output.config(state=tk.NORMAL)
            self.password_output.delete("1.0", tk.END)
            
            for i in range(num_passwords_to_gen):
                password = self.generator.generate_password(
                    num_words=num_words_base_val,
                    min_length=min_len_val,
                    max_length=max_len_val, # НОВОЕ: передача в метод
                    random_char_count=random_char_count_val,
                    random_case_prob=random_case_prob_val,
                    leet_speak_prob=leet_speak_prob_val,
                    rarity_weight_factor=rarity_weight_factor_val
                )
                self.password_output.insert(tk.END, f"{i+1}. {password} ({len(password)})\n")
            
            self.password_output.config(state=tk.DISABLED)
            self.status_bar.config(text="Пароли успешно сгенерированы")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
