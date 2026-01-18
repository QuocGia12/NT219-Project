# Hastad Attack
## Giới thiệu 
Cho `e` là các số nguyên tố nhỏ thuộc `[3, 61]`, ứng với mỗi `e` thực hiện mã hóa cùng một plaintext với `k=e` modulo `n` khác nhau, kiểm tra có thực hiện thành công **Hastad broadcast attack** hay không, số liệu thu về được lưu trong `/logs/hastad_attack/results.csv`.

## Hướng dẫn build/run containter   
Ở thư mục gốc
```bash 
docker build -t hastad-attack -f docker/hastad-attack/Dockerfile .

docker run --rm   -v $(pwd)/logs:/logs   hastad-attack
```



