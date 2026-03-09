import os
import re
from typing import Set, List, Tuple, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

from analyzers.base_analyzer import BaseAnalyzer
from core.models import ModuleResult, Finding, Severity

if TYPE_CHECKING:
    from analyzers.dictionary_analyzer import DictionaryAnalyzer

LEET_MAP = {
    '@': ['a'],
    '4': ['a'],
    '3': ['e'],
    '1': ['i', 'l'],
    '!': ['i', 'l'],
    '0': ['o'],
    '$': ['s'],
    '5': ['s'],
    '7': ['t'],
    '+': ['t'],
    '8': ['b'],
    '(': ['c'],
    '9': ['g'],
    '6': ['g'],
}

YEAR_PATTERN = re.compile(r'(19[5-9]\d|20[0-3]\d)$')
TRAILING_DIGITS = re.compile(r'[0-9]{1,4}$')
TRAILING_SPECIALS = re.compile(r'[^a-zA-Z0-9]+$')
LEADING_SPECIALS = re.compile(r'^[^a-zA-Z0-9]+')

# ── Hashcat Rule Engine ──────────────────────────────────────

# Операции без аргументов
NO_ARG_OPS = set(':lucCtrdfq{}[]kKE')
# Операции с 1-символьным аргументом
ONE_ARG_OPS = set('$^@TDzZpLR\'')
# Операции с 2-символьными аргументами
TWO_ARG_OPS = set('sioOxX')


@dataclass
class ParsedRule:
    raw: str
    operations: List[Tuple[str, Optional[str]]] = field(default_factory=list)


def parse_rule(rule_str: str) -> Optional[ParsedRule]:
    ops = []
    i = 0
    while i < len(rule_str):
        ch = rule_str[i]
        if ch in NO_ARG_OPS:
            ops.append((ch, None))
            i += 1
        elif ch in ONE_ARG_OPS:
            if i + 1 < len(rule_str):
                ops.append((ch, rule_str[i + 1]))
                i += 2
            else:
                return None
        elif ch in TWO_ARG_OPS:
            if i + 2 < len(rule_str):
                ops.append((ch, rule_str[i + 1] + rule_str[i + 2]))
                i += 3
            else:
                return None
        elif ch == ' ' or ch == '\t':
            i += 1
        else:
            i += 1
    return ParsedRule(raw=rule_str, operations=ops)


def apply_rule_forward(word: str, rule: ParsedRule) -> Optional[str]:
    result = word
    for op, arg in rule.operations:
        result = _apply_op_forward(result, op, arg)
        if result is None:
            return None
    return result


def _apply_op_forward(word: str, op: str, arg) -> Optional[str]:
    if not word and op != ':':
        return word
    if op == ':': return word
    if op == 'l': return word.lower()
    if op == 'u': return word.upper()
    if op == 'c': return word[0].upper() + word[1:].lower() if word else word
    if op == 'C': return word[0].lower() + word[1:].upper() if word else word
    if op == 't': return word.swapcase()
    if op == 'r': return word[::-1]
    if op == 'd': return word + word
    if op == 'f': return word + word[::-1]
    if op == 'q': return ''.join(c * 2 for c in word)
    if op == '{': return word[1:] + word[0] if word else word
    if op == '}': return word[-1] + word[:-1] if word else word
    if op == '[': return word[1:]
    if op == ']': return word[:-1]
    if op == 'k': return word[1] + word[0] + word[2:] if len(word) >= 2 else word
    if op == 'K': return word[:-2] + word[-1] + word[-2] if len(word) >= 2 else word
    if op == '$' and arg: return word + arg
    if op == '^' and arg: return arg + word
    if op == '@' and arg: return word.replace(arg, '')
    if op == 's' and arg and len(arg) == 2:
        return word.replace(arg[0], arg[1])
    if op == 'T' and arg:
        pos = int(arg) if arg.isdigit() else -1
        if 0 <= pos < len(word):
            c = word[pos]
            c = c.lower() if c.isupper() else c.upper()
            return word[:pos] + c + word[pos + 1:]
        return word
    if op == 'D' and arg:
        pos = int(arg) if arg.isdigit() else -1
        if 0 <= pos < len(word):
            return word[:pos] + word[pos + 1:]
        return word
    if op == 'z' and arg:
        n = int(arg) if arg.isdigit() else 0
        return word[0] * n + word if word and n > 0 else word
    if op == 'Z' and arg:
        n = int(arg) if arg.isdigit() else 0
        return word + word[-1] * n if word and n > 0 else word
    if op == 'p' and arg:
        n = int(arg) if arg.isdigit() else 0
        return word * (n + 1) if n > 0 else word
    if op == 'i' and arg and len(arg) == 2:
        pos = int(arg[0]) if arg[0].isdigit() else -1
        if 0 <= pos <= len(word):
            return word[:pos] + arg[1] + word[pos:]
        return word
    if op == 'o' and arg and len(arg) == 2:
        pos = int(arg[0]) if arg[0].isdigit() else -1
        if 0 <= pos < len(word):
            return word[:pos] + arg[1] + word[pos + 1:]
        return word
    if op == "'":
        n = int(arg) if arg and arg.isdigit() else -1
        if n >= 0:
            return word[:n]
        return word
    return word


def reverse_rule(password: str, rule: ParsedRule) -> Optional[str]:
    candidate = password
    for op, arg in reversed(rule.operations):
        candidate = _reverse_op(candidate, op, arg)
        if candidate is None:
            return None
    return candidate


def _reverse_op(text: str, op: str, arg) -> Optional[str]:
    if not text:
        return None
    if op == ':': return text
    if op == 'l': return text
    if op == 'u': return text.lower()
    if op == 'c':
        if text and text[0].isupper():
            return text.lower()
        return None
    if op == 'C':
        if text and text[0].islower():
            return text[0].upper() + text[1:].lower()
        return None
    if op == 't': return text.swapcase()
    if op == 'r': return text[::-1]
    if op == 'd':
        if len(text) % 2 == 0:
            h = len(text) // 2
            if text[:h] == text[h:]:
                return text[:h]
        return None
    if op == 'f':
        if len(text) % 2 == 0:
            h = len(text) // 2
            if text[:h] == text[h:][::-1]:
                return text[:h]
        return None
    if op == 'q':
        if len(text) % 2 == 0:
            result = []
            for i in range(0, len(text), 2):
                if text[i] == text[i + 1]:
                    result.append(text[i])
                else:
                    return None
            return ''.join(result)
        return None
    if op == '$' and arg:
        if text and text[-1] == arg:
            return text[:-1]
        return None
    if op == '^' and arg:
        if text and text[0] == arg:
            return text[1:]
        return None
    if op == 's' and arg and len(arg) == 2:
        return text.replace(arg[1], arg[0])
    if op == '{':
        return text[-1] + text[:-1] if text else text
    if op == '}':
        return text[1:] + text[0] if text else text
    if op == 'z' and arg:
        n = int(arg) if arg.isdigit() else 0
        if n > 0 and len(text) > n:
            if all(text[i] == text[0] for i in range(n)):
                return text[n:]
        return None
    if op == 'Z' and arg:
        n = int(arg) if arg.isdigit() else 0
        if n > 0 and len(text) > n:
            if all(text[-(i + 1)] == text[-1] for i in range(n)):
                return text[:-n]
        return None
    if op == 'p' and arg:
        n = int(arg) if arg.isdigit() else 0
        total = n + 1
        if total > 1 and len(text) % total == 0:
            chunk_len = len(text) // total
            chunk = text[:chunk_len]
            if text == chunk * total:
                return chunk
        return None
    # Операции с потерей информации — не обратимы
    return None


# ── Rule Analyzer ────────────────────────────────────────────

class RuleAnalyzer(BaseAnalyzer):

    def __init__(self, dictionary_analyzer: 'DictionaryAnalyzer'):
        self._dict_analyzer = dictionary_analyzer
        self._hashcat_rules: List[ParsedRule] = []
        self._loaded_file: Optional[str] = None
        self._loaded_count: int = 0

    @property
    def name(self) -> str:
        return "Анализ правил (Rule-Based)"

    @property
    def dictionary(self) -> Set[str]:
        return self._dict_analyzer.dictionary

    @property
    def loaded_rules_info(self) -> str:
        if self._loaded_file:
            return f"{os.path.basename(self._loaded_file)} ({self._loaded_count})"
        return "не загружены"

    def load_rules(self, filepath: str):
        rules = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parsed = parse_rule(line)
                if parsed and parsed.operations:
                    rules.append(parsed)
        self._hashcat_rules = rules
        self._loaded_file = filepath
        self._loaded_count = len(rules)

    def analyze(self, password: str) -> ModuleResult:
        findings = []
        recommendations = []

        if not self.dictionary:
            return ModuleResult(
                module_name=self.name,
                score=1.0,
                findings=[Finding("Словарь не загружен — анализ правил невозможен",
                                  Severity.INFO, 0.0)],
            )

        # 1. Встроенный анализ: leet-speak + суффиксы/префиксы
        builtin_match = self._builtin_analysis(password)

        # 2. Анализ загруженных правил Hashcat
        hashcat_match = self._hashcat_analysis(password) if self._hashcat_rules else None

        # Выбираем лучший (худший для пароля) результат
        best_match = None
        if builtin_match and hashcat_match:
            best_match = builtin_match if builtin_match[1] >= hashcat_match[1] else hashcat_match
        elif builtin_match:
            best_match = builtin_match
        elif hashcat_match:
            best_match = hashcat_match

        if best_match:
            word, penalty, description = best_match
            findings.append(Finding(
                f"Пароль является модификацией словарного слова «{word}»",
                Severity.CRITICAL if penalty >= 0.7 else Severity.HIGH,
                penalty,
                detail=description,
            ))
            recommendations.append(
                "Не используйте модифицированные словарные слова — "
                "атакующие применяют те же правила замены"
            )
            if self._has_leet(password):
                recommendations.append(
                    "Замены вроде @→a, 0→o, $→s не повышают стойкость пароля"
                )
            score = max(0.0, 1.0 - penalty)
        else:
            # Проверяем наличие типичных трансформаций без словарного совпадения
            penalty = 0.0
            if self._has_leet(password):
                findings.append(Finding(
                    "Обнаружены leet-speak замены символов",
                    Severity.LOW, 0.05,
                ))
                penalty += 0.05

            if self._has_year_suffix(password):
                findings.append(Finding(
                    "Пароль заканчивается на год",
                    Severity.LOW, 0.05,
                ))
                recommendations.append("Избегайте добавления года в конец пароля")
                penalty += 0.05

            if self._is_only_capitalized(password):
                findings.append(Finding(
                    "Только первая буква заглавная — типичная трансформация",
                    Severity.LOW, 0.03,
                ))
                penalty += 0.03

            if not findings:
                findings.append(Finding(
                    "Типичные трансформации не обнаружены",
                    Severity.INFO, 0.0,
                ))

            score = max(0.0, 1.0 - penalty)

        return ModuleResult(self.name, score, findings, recommendations)

    # ── Встроенный анализ ─────────────────────────────────────

    def _builtin_analysis(self, password: str) -> Optional[Tuple[str, float, str]]:
        candidates = self._generate_candidates(password)
        best_match = None
        for base_word, transforms_count in candidates:
            if base_word.lower() in self.dictionary and transforms_count > 0:
                if best_match is None or transforms_count < best_match[1]:
                    best_match = (base_word, transforms_count)

        if best_match:
            word, count = best_match
            if count == 1:
                penalty = 0.85
            elif count <= 3:
                penalty = 0.70
            else:
                penalty = 0.50
            desc = f"Обнаруженные трансформации: {self._describe_transforms(password, word)}"
            return (word, penalty, desc)
        return None

    # ── Анализ правил Hashcat ─────────────────────────────────

    def _hashcat_analysis(self, password: str) -> Optional[Tuple[str, float, str]]:
        for rule in self._hashcat_rules:
            candidate = reverse_rule(password, rule)
            if candidate and len(candidate) >= 3 and candidate.lower() in self.dictionary:
                if candidate.lower() != password.lower():
                    penalty = 0.80
                    desc = f"Правило Hashcat: {rule.raw}"
                    return (candidate, penalty, desc)
        return None

    # ── Генерация кандидатов (leet-speak / суффиксы) ──────────

    def _generate_candidates(self, password: str) -> List[Tuple[str, int]]:
        candidates = []
        variants = [(password, 0)]

        leet_reversed = self._reverse_leet(password)
        for word in leet_reversed:
            if word != password:
                diff = sum(1 for a, b in zip(password.lower(), word.lower()) if a != b)
                variants.append((word, max(1, diff)))

        expanded = []
        for word, count in variants:
            expanded.append((word, count))
            lower_word = word[0].lower() + word[1:] if word and word[0].isupper() else None
            if lower_word and lower_word != word:
                expanded.append((lower_word, count + 1))
            if word.lower() != word:
                expanded.append((word.lower(), count + 1))

        final = []
        for word, count in expanded:
            final.append((word, count))
            w = word
            c = count

            stripped = TRAILING_SPECIALS.sub('', w)
            if stripped and stripped != w:
                c += 1
                w = stripped
                final.append((w, c))

            year_match = YEAR_PATTERN.search(w)
            if year_match:
                w_no_year = w[:year_match.start()]
                if w_no_year and len(w_no_year) >= 3:
                    final.append((w_no_year, c + 1))

            w2 = TRAILING_DIGITS.sub('', w)
            if w2 and w2 != w and len(w2) >= 3:
                final.append((w2, c + 1))

            w3 = LEADING_SPECIALS.sub('', w)
            if w3 and w3 != w and len(w3) >= 3:
                final.append((w3, c + 1))

        candidates = [(w.lower(), c) for w, c in final if len(w) >= 3]
        return candidates

    def _reverse_leet(self, password: str) -> List[str]:
        results = ['']
        for ch in password:
            lower_ch = ch.lower()
            if ch in LEET_MAP:
                replacements = LEET_MAP[ch] + [lower_ch]
            elif lower_ch in LEET_MAP:
                replacements = LEET_MAP[lower_ch] + [lower_ch]
            else:
                replacements = [lower_ch]

            new_results = []
            for r in results:
                for rep in replacements:
                    new_results.append(r + rep)
                    if len(new_results) > 100:
                        break
                if len(new_results) > 100:
                    break
            results = new_results[:100]

        return list(set(results))

    # ── Вспомогательные ──────────────────────────────────────

    def _has_leet(self, password: str) -> bool:
        return any(ch in LEET_MAP for ch in password)

    def _has_year_suffix(self, password: str) -> bool:
        return bool(YEAR_PATTERN.search(password))

    def _is_only_capitalized(self, password: str) -> bool:
        if len(password) < 2:
            return False
        return password[0].isupper() and password[1:].islower()

    def _describe_transforms(self, original: str, base: str) -> str:
        parts = []
        if self._has_leet(original):
            parts.append("leet-speak замены")
        if self._is_only_capitalized(original):
            parts.append("капитализация первой буквы")
        if self._has_year_suffix(original):
            parts.append("добавление года")
        if TRAILING_DIGITS.search(original):
            parts.append("цифры в конце")
        if TRAILING_SPECIALS.search(original):
            parts.append("спецсимволы в конце")
        return ", ".join(parts) if parts else "стандартные преобразования"
