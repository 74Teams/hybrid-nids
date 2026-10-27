import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Từ tiếng Việt thường gặp khi viết không dấu. "trong" không nằm trong danh sách vì
# đó là cách viết đúng của từ "trong" (có dấu hay không đều như nhau).
UNACCENTED = re.compile(
    r"\b(khong|duoc|dang|chua|cua|nhung|voi|luat|nap|loi|thanh cong|phat hien|"
    r"goi tin|xu ly|ket noi|khoi dong|canh bao|thieu|phai|dau|cuoi cung|rong|thua|"
    r"tham so|hop le|ho tro|bat dau|mac dinh|quyet dinh|tiet kiem|gia tri|doan|"
    r"tap hop|phan tich|giai ma|bo qua|ghi nhan)\b",
    re.IGNORECASE,
)


def python_files():
    files = []
    for folder in ("nids", "lab", "tests"):
        files += (ROOT / folder).rglob("*.py")
    return [f for f in files if f.name != "test_code_language.py"]


def test_no_unaccented_vietnamese():
    offenders = []
    for path in python_files():
        source = path.read_text(encoding="utf-8")
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING) and UNACCENTED.search(token.string):
                offenders.append(f"{path.relative_to(ROOT)}:{token.start[0]}")
    assert offenders == []
