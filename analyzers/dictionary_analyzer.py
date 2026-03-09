import os
import re
from typing import Set, Optional, Tuple

from analyzers.base_analyzer import BaseAnalyzer
from core.models import ModuleResult, Finding, Severity


class DictionaryAnalyzer(BaseAnalyzer):

    def __init__(self):
        self._dictionary: Set[str] = set()
        self._loaded_file: Optional[str] = None
        self._loaded_count: int = 0
        self._load_default()

    @property
    def name(self) -> str:
        return "Словарный анализ"

    @property
    def dictionary(self) -> Set[str]:
        return self._dictionary

    @property
    def loaded_info(self) -> str:
        if self._loaded_file:
            return f"{os.path.basename(self._loaded_file)} ({self._loaded_count})"
        return f"встроенный ({self._loaded_count})"

    def _load_default(self):
        default_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "default_dictionary.txt",
        )
        if os.path.isfile(default_path):
            self._load_file(default_path, is_default=True)

    def load_dictionary(self, filepath: str):
        self._load_file(filepath, is_default=False)

    def _load_file(self, filepath: str, is_default: bool = False):
        words = set()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and len(word) >= 3 and len(word) <= 30:
                    words.add(word.lower())
        self._dictionary = words
        self._loaded_count = len(words)
        if not is_default:
            self._loaded_file = filepath

    def analyze(self, password: str) -> ModuleResult:
        findings = []
        recommendations = []
        total_penalty = 0.0
        pw_lower = password.lower()

        if not self._dictionary:
            return ModuleResult(
                module_name=self.name,
                score=1.0,
                findings=[Finding("Словарь не загружен", Severity.INFO, 0.0)],
                recommendations=["Загрузите файл словаря для словарного анализа"],
            )

        # 1. Точное совпадение
        if pw_lower in self._dictionary:
            findings.append(Finding(
                f"Пароль «{password}» найден в словаре",
                Severity.CRITICAL, 1.0,
            ))
            recommendations.append("Не используйте пароль, входящий в словарь популярных паролей")
            return ModuleResult(self.name, 0.0, findings, recommendations)

        # 2. Совпадение без крайних цифр/символов
        stripped = re.sub(r'^[^a-zA-Zа-яА-Я]+|[^a-zA-Zа-яА-Я]+$', '', pw_lower)
        if stripped and len(stripped) >= 3 and stripped in self._dictionary:
            findings.append(Finding(
                f"Основа «{stripped}» найдена в словаре (без крайних символов)",
                Severity.CRITICAL, 0.9,
                detail=f"Оригинал: {password} → основа: {stripped}",
            ))
            recommendations.append(
                "Не используйте словарное слово с добавлением цифр/символов по краям"
            )
            total_penalty = 0.9
        else:
            # 3. Поиск подстроки
            match_word, match_penalty = self._find_substring_match(pw_lower)
            if match_word:
                findings.append(Finding(
                    f"Словарное слово «{match_word}» обнаружено как часть пароля",
                    Severity.HIGH, match_penalty,
                    detail=f"Покрытие: {len(match_word)}/{len(password)} символов",
                ))
                recommendations.append(
                    "Избегайте использования словарных слов как части пароля"
                )
                total_penalty = match_penalty

        if not findings:
            findings.append(Finding(
                "Совпадений со словарём не обнаружено",
                Severity.INFO, 0.0,
            ))

        score = max(0.0, min(1.0, 1.0 - total_penalty))
        return ModuleResult(self.name, score, findings, recommendations)

    def _find_substring_match(self, pw_lower: str) -> Tuple[Optional[str], float]:
        best_word = None
        best_len = 0
        pw_len = len(pw_lower)

        for k in range(min(pw_len, 30), 3, -1):
            for i in range(pw_len - k + 1):
                substr = pw_lower[i:i + k]
                if substr in self._dictionary:
                    if len(substr) > best_len:
                        best_word = substr
                        best_len = len(substr)
            if best_word:
                break

        if best_word:
            coverage = best_len / pw_len
            penalty = coverage * 0.8
            return best_word, penalty
        return None, 0.0
