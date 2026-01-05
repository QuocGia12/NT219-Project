# config.py

# Target configuration
HOST = "127.0.0.1"
PORT = 9999

# Timing Configuration
# Vì server dùng BigNum CPU load, thời gian sẽ dao động.
SAMPLES_CALIB = 100       # Số mẫu dùng để tính ngưỡng (Threshold) lúc đầu
SAMPLES_PER_QUERY = 1   # Số mẫu cho mỗi lần đoán trong khi tấn công
TIMEOUT = 1000             # Socket timeout