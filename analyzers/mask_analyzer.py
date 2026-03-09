import os
import re
from typing import Set, Optional, Tuple, TYPE_CHECKING

from analyzers.base_analyzer import BaseAnalyzer
from core.models import ModuleResult, Finding, Severity

if TYPE_CHECKING:
    from analyzers.dictionary_analyzer import DictionaryAnalyzer

YEAR_PATTERN = re.compile(r'(19[5-9]\d|20[0-3]\d)$')
WORD_NUMBER_PATTERN = re.compile(r'^[a-zA-Zа-яА-Я]{3,}[0-9]{1,4}$')


class MaskAnalyzer(BaseAnalyzer):

    def __init__(self, dictionary_analyzer: 'DictionaryAnalyzer'):
        self._dict_analyzer = dictionary_analyzer
        self._names: Set[str] = set()
        self._load_default_names()

    @property
    def name(self) -> str:
        return "Структурный и комбинаторный анализ"

    @property
    def dictionary(self) -> Set[str]:
        return self._dict_analyzer.dictionary

    def _load_default_names(self):
        names_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "common_names.txt",
        )
        if os.path.isfile(names_path):
            with open(names_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    name = line.strip().lower()
                    if name and len(name) >= 2:
                        self._names.add(name)

    def analyze(self, password: str) -> ModuleResult:
        findings = []
        recommendations = []
        total_penalty = 0.0

        # 1a. word+number
        if WORD_NUMBER_PATTERN.match(password):
            alpha_part = re.match(r'^[a-zA-Zа-яА-Я]+', password).group()
            digit_part = re.search(r'[0-9]+$', password).group()
            penalty = 0.5
            detail = f"Структура: «{alpha_part}» + «{digit_part}»"

            if alpha_part.lower() in self.dictionary:
                penalty = 0.75
                detail += " (словарное слово + число)"

            findings.append(Finding(
                "Обнаружена структура «слово + число»",
                Severity.HIGH if penalty >= 0.7 else Severity.MEDIUM,
                penalty,
                detail=detail,
            ))
            recommendations.append(
                "Избегайте структуры «слово + число» — она легко подбирается"
            )
            total_penalty = max(total_penalty, penalty)

        # 1b. name+year
        name_year_penalty = self._check_name_year(password)
        if name_year_penalty > 0:
            findings.append(Finding(
                "Обнаружена структура «имя + год»",
                Severity.HIGH, name_year_penalty,
            ))
            recommendations.append(
                "Не используйте комбинацию имени и года — это распространённый шаблон"
            )
            total_penalty = max(total_penalty, name_year_penalty)

        # 1c. Два коротких слова
        combo_match = self._check_two_words(password)
        if combo_match:
            word1, word2 = combo_match
            findings.append(Finding(
                f"Пароль состоит из двух словарных слов: «{word1}» + «{word2}»",
                Severity.HIGH, 0.7,
                detail="Уязвим к комбинаторной атаке",
            ))
            recommendations.append(
                "Не склеивайте два простых слова — используйте случайные символы между ними"
            )
            total_penalty = max(total_penalty, 0.7)

        # 1d. Повторяющиеся блоки
        repeat_penalty = self._check_repeating_blocks(password)
        if repeat_penalty > 0:
            findings.append(Finding(
                "Пароль состоит из повторяющихся блоков",
                Severity.HIGH, repeat_penalty,
            ))
            recommendations.append("Не повторяйте одну и ту же последовательность символов")
            total_penalty = max(total_penalty, repeat_penalty)

        if not findings:
            findings.append(Finding(
                "Структурных уязвимостей не обнаружено",
                Severity.INFO, 0.0,
            ))

        score = max(0.0, min(1.0, 1.0 - total_penalty))
        return ModuleResult(self.name, score, findings, recommendations)

    def _check_name_year(self, password: str) -> float:
        if len(password) < 6:
            return 0.0
        year_match = YEAR_PATTERN.search(password)
        if not year_match:
            return 0.0
        prefix = password[:year_match.start()].lower()
        if prefix in self._names:
            return 0.8
        if prefix in self.dictionary:
            return 0.6
        return 0.0

    def _check_two_words(self, password: str) -> Optional[Tuple[str, str]]:
        if not self.dictionary:
            return None
        pw_lower = password.lower()
        for i in range(3, len(pw_lower) - 2):
            left = pw_lower[:i]
            right = pw_lower[i:]
            if left in self.dictionary and right in self.dictionary:
                return (left, right)
        return None

    def _check_repeating_blocks(self, password: str) -> float:
        length = len(password)
        if length < 4:
            return 0.0
        for block_len in range(1, length // 2 + 1):
            block = password[:block_len]
            repeated = (block * (length // block_len + 1))[:length]
            if repeated == password:
                return 0.8 if block_len <= 3 else 0.5
        return 0.0
