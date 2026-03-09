from typing import Optional, Tuple, List, Dict

from analyzers.base_analyzer import BaseAnalyzer
from core.models import ModuleResult, Finding, Severity

QWERTY_ROWS = [
    ['`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '='],
    ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\\'],
    ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', "'"],
    ['z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/'],
]

SHIFT_MAP = {
    '`': '~', '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
    '6': '^', '7': '&', '8': '*', '9': '(', '0': ')', '-': '_',
    '=': '+', '[': '{', ']': '}', '\\': '|', ';': ':', "'": '"',
    ',': '<', '.': '>', '/': '?',
}

NUMPAD_ROWS = [
    ['7', '8', '9'],
    ['4', '5', '6'],
    ['1', '2', '3'],
    ['0'],
]

KNOWN_PATTERNS = [
    "qwerty", "qwertyuiop", "qwert", "werty", "asdfg", "asdfgh",
    "asdfghjkl", "zxcvbn", "zxcvbnm", "qazwsx", "1qaz2wsx",
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
    "zaq1", "xsw2", "cde3", "vfr4", "bgt5", "nhy6", "mju7",
    "1q2w3e", "1q2w3e4r", "q1w2e3r4",
    "123456", "12345678", "1234567890", "123456789",
    "987654321", "0987654321",
    "abcdef", "abcdefgh",
    "!qaz", "!qaz@wsx", "@wsx", "#edc",
]


class KeyboardAnalyzer(BaseAnalyzer):

    def __init__(self):
        self._key_positions: Dict[str, Tuple[int, int]] = {}
        self._build_positions()

    @property
    def name(self) -> str:
        return "Клавиатурные шаблоны"

    def _build_positions(self):
        for row_idx, row in enumerate(QWERTY_ROWS):
            for col_idx, key in enumerate(row):
                self._key_positions[key] = (row_idx, col_idx)
                if key in SHIFT_MAP:
                    self._key_positions[SHIFT_MAP[key]] = (row_idx, col_idx)
                if key.isalpha():
                    self._key_positions[key.upper()] = (row_idx, col_idx)

        for row_idx, row in enumerate(NUMPAD_ROWS):
            for col_idx, key in enumerate(row):
                if key not in self._key_positions:
                    self._key_positions[key] = (row_idx + 10, col_idx)

    def analyze(self, password: str) -> ModuleResult:
        findings = []
        recommendations = []
        total_penalty = 0.0

        # 1. Проверка известных паттернов
        known_penalty, known_pattern = self._check_known_patterns(password)
        if known_penalty > 0:
            coverage = len(known_pattern) / len(password) if password else 0
            findings.append(Finding(
                f"Обнаружена известная клавиатурная последовательность «{known_pattern}»",
                Severity.CRITICAL if coverage > 0.7 else Severity.HIGH,
                known_penalty,
                detail=f"Покрытие: {len(known_pattern)}/{len(password)} символов",
            ))
            recommendations.append("Не используйте клавиатурные последовательности как пароль")
            total_penalty = max(total_penalty, known_penalty)

        # 2. Пространственный анализ
        walk_len, walk_start = self._detect_spatial_walk(password)
        if walk_len >= 4:
            walk_coverage = walk_len / len(password) if password else 0
            if walk_coverage > 0.8:
                walk_penalty = 0.9
            elif walk_coverage > 0.5:
                walk_penalty = 0.6
            elif walk_coverage > 0.3:
                walk_penalty = 0.3
            else:
                walk_penalty = 0.1

            if walk_penalty > known_penalty:
                findings.append(Finding(
                    f"Обнаружена клавиатурная прогулка длиной {walk_len} символов",
                    Severity.HIGH if walk_penalty >= 0.5 else Severity.MEDIUM,
                    walk_penalty,
                    detail=f"Начало с позиции {walk_start}",
                ))
                if not recommendations:
                    recommendations.append(
                        "Разбейте клавиатурную последовательность случайными символами"
                    )
                total_penalty = max(total_penalty, walk_penalty)

        # 3. Проверка простых числовых последовательностей
        seq_penalty = self._check_sequential(password)
        if seq_penalty > 0:
            findings.append(Finding(
                "Обнаружена последовательность символов (abc..., 123...)",
                Severity.MEDIUM, seq_penalty,
            ))
            total_penalty = max(total_penalty, seq_penalty)

        if not findings:
            findings.append(Finding(
                "Клавиатурные шаблоны не обнаружены",
                Severity.INFO, 0.0,
            ))

        score = max(0.0, min(1.0, 1.0 - total_penalty))
        return ModuleResult(self.name, score, findings, recommendations)

    def _check_known_patterns(self, password: str) -> Tuple[float, str]:
        pw_lower = password.lower()
        # Собираем также нижний регистр от shifted-вариантов
        unshifted = self._unshift(password).lower()

        best_penalty = 0.0
        best_pattern = ""

        for pattern in KNOWN_PATTERNS:
            for text in (pw_lower, unshifted):
                if pattern in text:
                    coverage = len(pattern) / len(password) if password else 0
                    if coverage > 0.8:
                        penalty = 0.9
                    elif coverage > 0.5:
                        penalty = 0.6
                    elif coverage > 0.3:
                        penalty = 0.3
                    else:
                        penalty = 0.15
                    if penalty > best_penalty:
                        best_penalty = penalty
                        best_pattern = pattern

        return best_penalty, best_pattern

    def _unshift(self, password: str) -> str:
        reverse_shift = {v: k for k, v in SHIFT_MAP.items()}
        result = []
        for ch in password:
            if ch in reverse_shift:
                result.append(reverse_shift[ch])
            else:
                result.append(ch)
        return ''.join(result)

    def _detect_spatial_walk(self, password: str) -> Tuple[int, int]:
        if len(password) < 4:
            return 0, 0

        best_len = 0
        best_start = 0
        current_len = 1
        current_start = 0

        for i in range(1, len(password)):
            if self._are_adjacent(password[i - 1], password[i]):
                current_len += 1
            else:
                if current_len > best_len:
                    best_len = current_len
                    best_start = current_start
                current_len = 1
                current_start = i

        if current_len > best_len:
            best_len = current_len
            best_start = current_start

        return best_len, best_start

    def _are_adjacent(self, c1: str, c2: str) -> bool:
        pos1 = self._key_positions.get(c1)
        pos2 = self._key_positions.get(c2)
        if pos1 is None or pos2 is None:
            return False
        # Исключаем позиции из разных раскладок (основная vs numpad)
        if (pos1[0] >= 10) != (pos2[0] >= 10):
            return False
        return abs(pos1[0] - pos2[0]) <= 1 and abs(pos1[1] - pos2[1]) <= 1

    def _check_sequential(self, password: str) -> float:
        if len(password) < 4:
            return 0.0

        max_seq = 1
        current_seq = 1
        for i in range(1, len(password)):
            if ord(password[i]) == ord(password[i - 1]) + 1:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            elif ord(password[i]) == ord(password[i - 1]) - 1:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 1

        if max_seq < 4:
            return 0.0

        coverage = max_seq / len(password)
        if coverage > 0.8:
            return 0.7
        elif coverage > 0.5:
            return 0.4
        elif coverage > 0.3:
            return 0.2
        return 0.1
