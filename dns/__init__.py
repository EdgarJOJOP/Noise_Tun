"""__init__.py"""

from .resolver import DoHResolver
from .fake_sni import FakeSNIGenerator

__all__ = ["DoHResolver", "FakeSNIGenerator"]
