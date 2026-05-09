import random
import string

def generate_code(length: int = 16) -> str:
    """Tạo license key ngẫu nhiên dạng XXXX-XXXX-XXXX-XXXX."""
    chars = string.ascii_uppercase + string.digits
    raw   = ''.join(random.choices(chars, k=length))
    # Chia thành nhóm 4 cho dễ đọc
    return '-'.join(raw[i:i+4] for i in range(0, length, 4))
