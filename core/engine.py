from typing import List

from core.models import AnalysisResult
from core.aggregator import Aggregator
from analyzers.string_analyzer import StringAnalyzer
from analyzers.dictionary_analyzer import DictionaryAnalyzer
from analyzers.rule_analyzer import RuleAnalyzer
from analyzers.keyboard_analyzer import KeyboardAnalyzer
from analyzers.mask_analyzer import MaskAnalyzer


class PasswordEngine:

    def __init__(self):
        self.string_analyzer = StringAnalyzer()
        self.dictionary_analyzer = DictionaryAnalyzer()
        self.rule_analyzer = RuleAnalyzer(self.dictionary_analyzer)
        self.keyboard_analyzer = KeyboardAnalyzer()
        self.mask_analyzer = MaskAnalyzer(self.dictionary_analyzer)
        self.aggregator = Aggregator()

    def analyze(self, password: str) -> AnalysisResult:
        results = [
            self.string_analyzer.analyze(password),
            self.dictionary_analyzer.analyze(password),
            self.rule_analyzer.analyze(password),
            self.keyboard_analyzer.analyze(password),
            self.mask_analyzer.analyze(password),
        ]
        return self.aggregator.aggregate(results, password)

    def load_dictionary(self, filepath: str):
        self.dictionary_analyzer.load_dictionary(filepath)

    def load_rules(self, filepath: str):
        self.rule_analyzer.load_rules(filepath)
