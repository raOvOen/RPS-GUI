from abc import ABC, abstractmethod
from core.models import ModuleResult


class BaseAnalyzer(ABC):

    @abstractmethod
    def analyze(self, password: str) -> ModuleResult:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...
