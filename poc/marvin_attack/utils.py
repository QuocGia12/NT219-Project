# utils.py
import math

def ceil(a, b):
    """Ceiling division: returns ceil(a / b)"""
    return (a + b - 1) // b

def floor(a, b):
    """Floor division: returns a // b"""
    return a // b

def i2b(integer, size):
    """Convert integer to bytes (big endian)"""
    return integer.to_bytes(size, 'big')

def extract_session_secret(m_int, k):
    """
    Trích xuất Session Secret từ message đã giải mã (PKCS#1 v1.5 unpadding).
    Format: 00 02 [padding != 0] 00 [secret]
    """
    try:
        m_bytes = i2b(m_int, k)
        # Kiểm tra header PKCS#1 v1.5
        if m_bytes[0:2] != b'\x00\x02':
            return None
        
        # Tìm byte 0x00 ngăn cách
        try:
            sep_index = m_bytes.index(b'\x00', 2)
            return m_bytes[sep_index + 1:] # Phần sau 0x00 là Secret
        except ValueError:
            return None
    except OverflowError:
        return None