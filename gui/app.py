import threading
import customtkinter as ctk
from tkinter import filedialog

from core.engine import PasswordEngine
from core.models import AnalysisResult, StrengthLevel, Severity

COLORS = {
    StrengthLevel.VERY_WEAK: "#E74C3C",
    StrengthLevel.WEAK: "#E67E22",
    StrengthLevel.MEDIUM: "#F1C40F",
    StrengthLevel.STRONG: "#2ECC71",
    StrengthLevel.VERY_STRONG: "#27AE60",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#E74C3C",
    Severity.HIGH: "#E67E22",
    Severity.MEDIUM: "#F1C40F",
    Severity.LOW: "#3498DB",
    Severity.INFO: "#95A5A6",
}


class PasswordApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Рекомендательная система проверки стойкости паролей")
        self.geometry("1050x720")
        self.minsize(900, 600)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.engine = PasswordEngine()
        self._debounce_id = None
        self._password_visible = False

        self._build_ui()

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # === Верхняя секция: заголовок ===
        header = ctk.CTkLabel(
            self, text="Рекомендательная система проверки стойкости паролей",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        header.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        # === Секция ввода пароля + индикатор ===
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_frame, text="Пароль:", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(15, 5), pady=10,
        )

        self.password_entry = ctk.CTkEntry(
            input_frame, show="●", font=ctk.CTkFont(size=14), height=36,
        )
        self.password_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.password_entry.bind('<KeyRelease>', self._on_key_release)

        self.toggle_btn = ctk.CTkButton(
            input_frame, text="👁", width=40, height=36,
            command=self._toggle_visibility,
        )
        self.toggle_btn.grid(row=0, column=2, padx=5, pady=10)

        self.check_btn = ctk.CTkButton(
            input_frame, text="Проверить", width=120, height=36,
            command=self._run_analysis,
        )
        self.check_btn.grid(row=0, column=3, padx=(5, 15), pady=10)

        # Чекбокс автоматической проверки
        self.auto_check_var = ctk.BooleanVar(value=True)
        self.auto_check_cb = ctk.CTkCheckBox(
            input_frame, text="Автоматическая проверка",
            variable=self.auto_check_var,
            font=ctk.CTkFont(size=12),
        )
        self.auto_check_cb.grid(row=1, column=0, columnspan=2, padx=15, pady=(0, 5), sticky="w")

        # Индикатор стойкости
        meter_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        meter_frame.grid(row=2, column=0, columnspan=4, padx=15, pady=(0, 10), sticky="ew")
        meter_frame.grid_columnconfigure(0, weight=1)

        self.strength_bar = ctk.CTkProgressBar(meter_frame, height=20)
        self.strength_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.strength_bar.set(0)

        self.score_label = ctk.CTkLabel(
            meter_frame, text="0 / 100", font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.score_label.grid(row=0, column=1)

        self.level_label = ctk.CTkLabel(
            input_frame, text="", font=ctk.CTkFont(size=15, weight="bold"),
        )
        self.level_label.grid(row=3, column=0, columnspan=4, pady=(0, 10))

        # === Основная секция: две колонки ===
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=2, column=0, padx=20, pady=(0, 15), sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=3)
        main_frame.grid_columnconfigure(1, weight=2)
        main_frame.grid_rowconfigure(0, weight=1)

        # Левая колонка — результаты анализа
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.grid(row=0, column=0, padx=(0, 5), sticky="nsew")
        left_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            left_frame, text="Результаты анализа",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self.modules_scroll = ctk.CTkScrollableFrame(left_frame)
        self.modules_scroll.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        left_frame.grid_columnconfigure(0, weight=1)

        # Правая колонка — рекомендации + файлы
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.grid(row=0, column=1, padx=(5, 0), sticky="nsew")
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right_frame, text="Рекомендации",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")

        self.recs_textbox = ctk.CTkTextbox(right_frame, font=ctk.CTkFont(size=13))
        self.recs_textbox.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.recs_textbox.configure(state="disabled")

        # Секция файлов
        files_frame = ctk.CTkFrame(right_frame)
        files_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        files_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            files_frame, text="Управление файлами",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, columnspan=2, padx=10, pady=(8, 5), sticky="w")

        ctk.CTkButton(
            files_frame, text="Загрузить словарь", width=160,
            command=self._load_dictionary,
        ).grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.dict_status = ctk.CTkLabel(
            files_frame, text=f"Словарь: {self.engine.dictionary_analyzer.loaded_info}",
            font=ctk.CTkFont(size=11),
        )
        self.dict_status.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkButton(
            files_frame, text="Загрузить правила", width=160,
            command=self._load_rules,
        ).grid(row=2, column=0, padx=10, pady=(0, 8), sticky="w")

        self.rules_status = ctk.CTkLabel(
            files_frame, text=f"Правила: {self.engine.rule_analyzer.loaded_rules_info}",
            font=ctk.CTkFont(size=11),
        )
        self.rules_status.grid(row=2, column=1, padx=10, pady=(0, 8), sticky="w")

    # ── Event Handlers ───────────────────────────────────────────

    def _on_key_release(self, event=None):
        if not self.auto_check_var.get():
            return
        if self._debounce_id is not None:
            self.after_cancel(self._debounce_id)
        self._debounce_id = self.after(300, self._run_analysis)

    def _toggle_visibility(self):
        self._password_visible = not self._password_visible
        self.password_entry.configure(show="" if self._password_visible else "●")
        self.toggle_btn.configure(text="🔒" if self._password_visible else "👁")

    def _load_dictionary(self):
        filepath = filedialog.askopenfilename(
            title="Выберите файл словаря",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
        if not filepath:
            return
        self.dict_status.configure(text="Загрузка...")

        def _load():
            try:
                self.engine.load_dictionary(filepath)
                info = self.engine.dictionary_analyzer.loaded_info
                self.after(0, lambda: self.dict_status.configure(
                    text=f"Словарь: {info}"))
                self.after(0, self._run_analysis)
            except Exception as e:
                self.after(0, lambda: self.dict_status.configure(
                    text=f"Ошибка: {e}"))

        threading.Thread(target=_load, daemon=True).start()

    def _load_rules(self):
        filepath = filedialog.askopenfilename(
            title="Выберите файл правил Hashcat",
            filetypes=[("Правила Hashcat", "*.rule"), ("Все файлы", "*.*")],
        )
        if not filepath:
            return
        self.rules_status.configure(text="Загрузка...")

        def _load():
            try:
                self.engine.load_rules(filepath)
                info = self.engine.rule_analyzer.loaded_rules_info
                self.after(0, lambda: self.rules_status.configure(
                    text=f"Правила: {info}"))
                self.after(0, self._run_analysis)
            except Exception as e:
                self.after(0, lambda: self.rules_status.configure(
                    text=f"Ошибка: {e}"))

        threading.Thread(target=_load, daemon=True).start()

    # ── Analysis ─────────────────────────────────────────────────

    def _run_analysis(self):
        password = self.password_entry.get()
        result = self.engine.analyze(password)
        self._update_ui(result)

    def _update_ui(self, result: AnalysisResult):
        # Индикатор
        color = COLORS.get(result.strength_level, "#95A5A6")
        self.strength_bar.configure(progress_color=color)
        self.strength_bar.set(result.overall_score / 100.0)
        self.score_label.configure(text=f"{result.overall_score:.0f} / 100")
        self.level_label.configure(text=result.strength_level.value, text_color=color)

        # Модули
        for widget in self.modules_scroll.winfo_children():
            widget.destroy()

        for module_result in result.module_results:
            self._create_module_card(module_result)

        # Рекомендации
        self.recs_textbox.configure(state="normal")
        self.recs_textbox.delete("1.0", "end")
        if result.top_recommendations:
            for i, rec in enumerate(result.top_recommendations, 1):
                self.recs_textbox.insert("end", f"{i}. {rec}\n\n")
        else:
            self.recs_textbox.insert("end", "Пароль не нуждается в улучшении.")
        self.recs_textbox.configure(state="disabled")

    def _create_module_card(self, module_result):
        card = ctk.CTkFrame(self.modules_scroll)
        card.pack(fill="x", padx=5, pady=3)
        card.grid_columnconfigure(0, weight=1)

        # Заголовок модуля
        score_pct = f"{module_result.score * 100:.0f}%"
        if module_result.score >= 0.8:
            score_color = "#27AE60"
        elif module_result.score >= 0.5:
            score_color = "#F1C40F"
        else:
            score_color = "#E74C3C"

        header_frame = ctk.CTkFrame(card, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=(8, 2))
        header_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header_frame, text=module_result.module_name,
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header_frame, text=score_pct,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=score_color,
        ).grid(row=0, column=1, sticky="e")

        # Findings
        for finding in module_result.findings:
            finding_frame = ctk.CTkFrame(card, fg_color="transparent")
            finding_frame.pack(fill="x", padx=15, pady=1)

            severity_color = SEVERITY_COLORS.get(finding.severity, "#95A5A6")
            ctk.CTkLabel(
                finding_frame,
                text=f"● {finding.description}",
                font=ctk.CTkFont(size=12),
                text_color=severity_color,
                wraplength=450,
                justify="left",
            ).pack(anchor="w")

            if finding.detail:
                ctk.CTkLabel(
                    finding_frame,
                    text=f"   {finding.detail}",
                    font=ctk.CTkFont(size=11),
                    text_color="#7F8C8D",
                    wraplength=430,
                    justify="left",
                ).pack(anchor="w")

        # Небольшой отступ снизу
        ctk.CTkFrame(card, height=5, fg_color="transparent").pack()
