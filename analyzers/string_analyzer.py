import re
from analyzers.base_analyzer import BaseAnalyzer
from core.models import ModuleResult, Finding, Severity


class StringAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "Базовый анализ строки"

    def analyze(self, password: str) -> ModuleResult:
        findings = []
        recommendations = []
        length = len(password)

        # --- Длина ---
        if length == 0:
            return ModuleResult(
                module_name=self.name,
                score=0.0,
                findings=[Finding("Пароль пуст", Severity.CRITICAL, 1.0)],
                recommendations=["Введите пароль для анализа"],
            )

        length_score = min(1.0, max(0.0, (length - 4) / 16))
        if length < 6:
            findings.append(Finding(
                f"Длина пароля: {length} символов — слишком короткий",
                Severity.CRITICAL, 0.4,
            ))
            recommendations.append("Используйте пароль длиной не менее 8 символов")
        elif length < 8:
            findings.append(Finding(
                f"Длина пароля: {length} символов — короткий",
                Severity.HIGH, 0.2,
            ))
            recommendations.append("Увеличьте длину пароля до 12+ символов")
        elif length < 12:
            findings.append(Finding(
                f"Длина пароля: {length} символов — приемлемо",
                Severity.LOW, 0.0,
            ))
        else:
            findings.append(Finding(
                f"Длина пароля: {length} символов — хорошо",
                Severity.INFO, 0.0,
            ))

        # --- Классы символов ---
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        classes = sum([has_lower, has_upper, has_digit, has_special])
        class_score = classes / 4.0

        if classes <= 1:
            findings.append(Finding(
                f"Использован только {classes} класс символов",
                Severity.HIGH, 0.3,
            ))
            recommendations.append(
                "Добавьте символы разных типов: заглавные, строчные, цифры, спецсимволы"
            )
        elif classes == 2:
            findings.append(Finding(
                f"Использовано {classes} класса символов",
                Severity.MEDIUM, 0.1,
            ))
            recommendations.append("Добавьте ещё типы символов для повышения стойкости")
        else:
            findings.append(Finding(
                f"Использовано {classes} класса(ов) символов",
                Severity.INFO, 0.0,
            ))

        # --- Разнообразие ---
        unique = len(set(password))
        diversity = unique / length
        if diversity < 0.4:
            findings.append(Finding(
                f"Низкое разнообразие символов: {unique} уникальных из {length}",
                Severity.HIGH, 0.25,
            ))
            recommendations.append("Используйте больше различных символов")
        elif diversity < 0.6:
            findings.append(Finding(
                f"Среднее разнообразие символов: {unique} уникальных из {length}",
                Severity.MEDIUM, 0.1,
            ))

        # --- Повторы ---
        max_repeat = 1
        current_repeat = 1
        for i in range(1, length):
            if password[i] == password[i - 1]:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1

        repeat_penalty = min(0.3, max_repeat / length) if max_repeat >= 3 else 0.0
        if max_repeat >= 3:
            findings.append(Finding(
                f"Обнаружена серия из {max_repeat} одинаковых символов подряд",
                Severity.MEDIUM, repeat_penalty,
            ))
            recommendations.append("Избегайте повторения одного символа подряд")

        # --- Монотонные паттерны чередования ---
        alternation_penalty = 0.0
        if length >= 6:
            alternation_penalty = self._check_alternation(password)
            if alternation_penalty > 0:
                findings.append(Finding(
                    "Обнаружен монотонный паттерн чередования символов",
                    Severity.MEDIUM, alternation_penalty,
                ))
                recommendations.append("Избегайте предсказуемого чередования символов")

        # --- Итоговая оценка ---
        score = (
            0.35 * length_score
            + 0.25 * class_score
            + 0.25 * diversity
            + 0.15 * (1.0 - repeat_penalty - alternation_penalty)
        )
        score = max(0.0, min(1.0, score))

        return ModuleResult(
            module_name=self.name,
            score=score,
            findings=findings,
            recommendations=recommendations,
        )

    def _check_alternation(self, password: str) -> float:
        if len(password) < 6:
            return 0.0

        def char_type(c):
            if c.islower():
                return 'l'
            if c.isupper():
                return 'u'
            if c.isdigit():
                return 'd'
            return 's'

        types = [char_type(c) for c in password]
        # Проверяем повторяющийся паттерн типов длиной 2 или 3
        for pat_len in (2, 3):
            pattern = types[:pat_len]
            if len(set(pattern)) < 2:
                continue
            repeats = 0
            for i in range(0, len(types) - pat_len + 1, pat_len):
                if types[i:i + pat_len] == pattern:
                    repeats += 1
                else:
                    break
            coverage = (repeats * pat_len) / len(types)
            if coverage >= 0.7:
                return min(0.15, coverage * 0.2)
        return 0.0
