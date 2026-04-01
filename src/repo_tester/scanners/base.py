from __future__ import annotations
from abc import ABC, abstractmethod
from repo_tester.context import RepoContext
from repo_tester.report import Finding


class BaseScanner(ABC):
    name: str
    priority: int  # 1=malicious, 2=supply_chain, 3=health

    @abstractmethod
    def scan(self, repo: RepoContext) -> list[Finding]:
        ...
