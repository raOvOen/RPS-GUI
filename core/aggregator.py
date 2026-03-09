from typing import List
from core.models import (
    ModuleResult, AnalysisResult, StrengthLevel, Severity,
)

MODULE_WEIGHTS = {
    "Базовый анализ строки": 0.15,
    "Словарный анализ": 0.30,
    "Анализ правил (Rule-Based)": 0.20,
    "Клавиатурные шаблоны": 0.15,
    "Структурный и комбинаторный анализ": 0.20,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _score_to_level(score: float) -> StrengthLevel:
    if score < 20:
        return StrengthLevel.VERY_WEAK
    if score < 40:
        return StrengthLevel.WEAK
    if score < 60:
        return StrengthLevel.MEDIUM
    if score < 80:
        return StrengthLevel.STRONG
    return StrengthLevel.VERY_STRONG


class Aggregator:

    def aggregate(self, results: List[ModuleResult], password: str) -> AnalysisResult:
        if not password:
            return AnalysisResult(
                overall_score=0.0,
                strength_level=StrengthLevel.VERY_WEAK,
                module_results=results,
                top_recommendations=["Введите пароль для анализа"],
            )

        # Взвешенная сумма
        weighted_score = 0.0
        for result in results:
            weight = MODULE_WEIGHTS.get(result.module_name, 0.15)
            weighted_score += result.score * weight

        final_score = weighted_score * 100

        # Критический порог: прямое словарное совпадение (score=0) — потолок 20
        if any(r.score == 0.0 for r in results):
            final_score = min(final_score, 20.0)
        # Серьёзная уязвимость (score < 0.2) — потолок 35
        elif any(r.score < 0.2 for r in results):
            final_score = min(final_score, 35.0)

        # Бонус за длинные и стойкие пароли
        if all(r.score > 0.8 for r in results) and len(password) >= 16:
            final_score = min(final_score + 5, 100.0)

        final_score = max(0.0, min(100.0, final_score))
        strength_level = _score_to_level(final_score)

        # Сбор рекомендаций
        all_recs = []
        for result in results:
            for rec in result.recommendations:
                if rec not in all_recs:
                    all_recs.append(rec)

        # Сортировка по severity (берём максимальный severity из findings модуля)
        def _module_max_severity(module_name: str) -> int:
            for r in results:
                if r.module_name == module_name and r.findings:
                    return min(SEVERITY_ORDER.get(f.severity, 4) for f in r.findings)
            return 4

        # Привязка рекомендаций к модулям для сортировки
        rec_with_priority = []
        for result in results:
            priority = _module_max_severity(result.module_name)
            for rec in result.recommendations:
                rec_with_priority.append((priority, rec))

        rec_with_priority.sort(key=lambda x: x[0])
        seen = set()
        top_recs = []
        for _, rec in rec_with_priority:
            if rec not in seen:
                seen.add(rec)
                top_recs.append(rec)
            if len(top_recs) >= 5:
                break

        return AnalysisResult(
            overall_score=round(final_score, 1),
            strength_level=strength_level,
            module_results=results,
            top_recommendations=top_recs,
        )
