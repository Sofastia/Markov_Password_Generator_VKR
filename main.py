import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
from cryptography.fernet import Fernet

# Импортируем логику из модуля
from generator.markov_generator import MarkovMnemonicPasswordGenerator, SecurityError

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Генератор мнемонических паролей (Secured Edition)")
        master.geometry("850x850") 

        self.generator = None
        self.is_trained = False
        # Генерируем ключ сессии для шифрования/дешифрования модели
        self.session_key = Fernet.generate_key() 

        self._setup_style()
        self._setup_widgets()

    def _setup_style(self):
        self.style = ttk.Style()
        self.style.configure("TFrame", padding=10, relief="groove", borderwidth=2)
        self.style.configure("TButton", padding=5)
        self.style.configure("TLabel", padding=5)

    def _setup_widgets(self):
        self.main_frame = ttk.Frame(self.master, padding="10 10 10 10")
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

        # --- Секция 2: Настройки цепи Маркова и Сохранение ---
        self.markov_frame = ttk.LabelFrame(self.main_frame, text="2. Работа с моделью", padding="10 10 10 10")
        self.markov_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(self.markov_frame, text="Порядок цепи:").grid(row=0, column=0, sticky="w")
        self.markov_order = tk.IntVar(value=2)
        ttk.Radiobutton(self.markov_frame, text="1", variable=self.markov_order, value=1).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(self.markov_frame, text="2", variable=self.markov_order, value=2).grid(row=0, column=2, sticky="w")

        self.train_button = ttk.Button(self.markov_frame, text="Обучить модель", command=self._train_model)
        self.train_button.grid(row=1, column=0, columnspan=3, pady=5)

        self.save_button = ttk.Button(self.markov_frame, text="Зашифровать и сохранить", command=self._save_model_secure)
        self.save_button.grid(row=2, column=0, columnspan=1, pady=5)
        self.load_button = ttk.Button(self.markov_frame, text="Загрузить из архива", command=self._load_model_secure)
        self.load_button.grid(row=2, column=1, columnspan=2, pady=5)

        # --- Секция 3: Настройки генерации паролей ---
        self.gen_settings_frame = ttk.LabelFrame(self.main_frame, text="3. Настройки генерации", padding="10 10 10 10")
        self.gen_settings_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Настройки (упрощенный код для виджетов)
        self._create_spinbox_setting(self.gen_settings_frame, "Количество паролей:", 0, 1, 20, 5, default=5)
        self._create_spinbox_setting(self.gen_settings_frame, "Базовое кол-во слов:", 1, 3, 10, 5, default=4)
        self._create_spinbox_setting(self.gen_settings_frame, "Мин. длина:", 2, 8, 32, 5, default=16, var_name='min_len')
        self._create_spinbox_setting(self.gen_settings_frame, "МАКС. длина:", 3, 10, 64, 5, default=32, var_name='max_len')
        self._create_spinbox_setting(self.gen_settings_frame, "Случайные вставки:", 4, 0, 10, 5, default=3, var_name='random_char_count')
        
        self._create_scale_setting(self.gen_settings_frame, "Вероятность регистра:", 5, 0.0, 1.0, default=0.2, var_name='random_case_prob')
        self._create_scale_setting(self.gen_settings_frame, "Leet Speak:", 6, 0.0, 1.0, default=0.1, var_name='leet_speak_prob')
        self._create_scale_setting(self.gen_settings_frame, "Редкость слов:", 7, 0.0, 2.0, default=0.0, var_name='rarity_weight_factor')

        self.generate_button = ttk.Button(self.gen_settings_frame, text="ГЕНЕРИРОВАТЬ ПАРОЛИ", command=self._generate_passwords, state=tk.DISABLED)
        self.generate_button.grid(row=8, column=0, columnspan=2, pady=10)

        # --- Секция 4: Результаты ---
        self.results_frame = ttk.LabelFrame(self.main_frame, text="4. Сгенерированные пароли", padding="10 10 10 10")
        self.results_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.password_output = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, width=70, height=10, state=tk.DISABLED)
        self.password_output.grid(row=0, column=0, sticky="ew")

        self.status_bar = ttk.Label(self.master, text=f"Безопасность: Ключ сессии сгенерирован. CSPRNG (secrets) активен.", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_spinbox_setting(self, parent, label_text, row, from_, to, width, default, var_name=None):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w")
        spinbox = ttk.Spinbox(parent, from_=from_, to=to, width=width)
        spinbox.set(default)
        spinbox.grid(row=row, column=1, sticky="w")
        if var_name: setattr(self, var_name, spinbox)
        return spinbox

    def _create_scale_setting(self, parent, label_text, row, from_, to, default, var_name):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w")
        scale = ttk.Scale(parent, from_=from_, to=to, orient="horizontal", length=120)
        scale.set(default)
        scale.grid(row=row, column=1, sticky="ew")
        setattr(self, var_name, scale)
        return scale

    # --- Методы GUI для работы с моделью ---

    def _save_model_secure(self):
        if not self.is_trained: 
            messagebox.showwarning("Предупреждение", "Сначала обучите модель!")
            return
        
        filepath = filedialog.asksaveasfilename(defaultextension=".aes", title="Сохранить зашифрованную матрицу")
        if filepath:
            try:
                self.generator.save_model_secure(filepath, self.session_key)
                messagebox.showinfo("ИБ", f"Модель зашифрована AES и сохранена.\nКлюч сессии: {self.session_key.decode()[:10]}...")
            except Exception as e:
                messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить модель: {e}")

    def _load_model_secure(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Model", "*.aes")])
        if filepath:
            try:
                # Создаем новый генератор, чтобы избежать конфликтов порядка цепи
                self.generator = MarkovMnemonicPasswordGenerator(order=self.markov_order.get())
                self.generator.load_model_secure(filepath, self.session_key)
                self.is_trained = True
                self.generate_button.config(state=tk.NORMAL)
                self.status_bar.config(text="Зашифрованная модель успешно загружена")
            except SecurityError as e:
                messagebox.showerror("Ошибка безопасности", str(e))
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось загрузить модель. Проверьте ключ сессии или файл: {e}")

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
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    corpus_text = f.read().strip()
            except Exception as e:
                messagebox.showerror("Ошибка чтения", f"Не удалось прочитать файл: {e}")
                return

        if not corpus_text: return

        try:
            self.generator = MarkovMnemonicPasswordGenerator(order=self.markov_order.get())
            self.generator.train(corpus_text)
            self.is_trained = True
            self.generate_button.config(state=tk.NORMAL)
            self.status_bar.config(text=f"Модель {self.markov_order.get()}-го порядка обучена и готова к работе!")
        except Exception as e:
            messagebox.showerror("Ошибка обучения", str(e))

    def _generate_passwords(self):
        try:
            # Сбор параметров
            params = {
                "num_words": int(self.num_words_base.get()),
                "min_length": int(self.min_len.get()),
                "max_length": int(self.max_len.get()),
                "random_char_count": int(self.random_char_count.get()),
                "random_case_prob": float(self.random_case_prob.get()),
                "leet_speak_prob": float(self.leet_speak_prob.get()),
                "rarity_weight_factor": float(self.rarity_weight_factor.get())
            }
            num_passwords_to_gen = int(self.num_passwords.get())

            self.password_output.config(state=tk.NORMAL)
            self.password_output.delete("1.0", tk.END)
            
            for i in range(num_passwords_to_gen):
                password = self.generator.generate_password(**params)
                self.password_output.insert(tk.END, f"{i+1}. {password} ({len(password)})\n")
            
            self.password_output.config(state=tk.DISABLED)
            self.status_bar.config(text="Пароли успешно сгенерированы")
        except Exception as e:
            messagebox.showerror("Ошибка генерации", f"Ошибка: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
