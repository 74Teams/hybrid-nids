from typing import List, Tuple, Any

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False

class MultiPatternMatcher:
    """
    Bộ so khớp đa chuỗi mẫu (Multi-pattern matcher).
    Sử dụng thuật toán Aho-Corasick để tìm kiếm hàng trăm chuỗi content trong payload
    chỉ trong 1 lần duyệt O(N).
    """

    def __init__(self):
        self.automaton = None
        self.patterns: List[Tuple[str, Any]] = []

    def add_pattern(self, pattern: str, data: Any) -> None:
        """Thêm một chuỗi mẫu cần tìm và dữ liệu liên kết (ví dụ Rule ID)."""
        self.patterns.append((pattern, data))

    def build(self) -> None:
        """Xây dựng cây Automaton Aho-Corasick."""
        if HAS_AHOCORASICK:
            self.automaton = ahocorasick.Automaton()
            for pattern, data in self.patterns:
                self.automaton.add_word(pattern, (pattern, data))
            self.automaton.make_automaton()

    def search(self, text: str) -> List[Tuple[str, Any]]:
        """Tìm tất cả các mẫu xuất hiện trong chuỗi text."""
        results = []
        if not text:
            return results

        if HAS_AHOCORASICK and self.automaton:
            for end_idx, (pattern, data) in self.automaton.iter(text):
                results.append((pattern, data))
        else:
            for pattern, data in self.patterns:
                if pattern in text:
                    results.append((pattern, data))

        return results
