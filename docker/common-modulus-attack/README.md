# Wiener Lab 
## Giới thiệu 
Containter thực hiện **Common modulus attack** trên các cặp `{e1, n}` và `{e2, n}` ngẫu nhiên, kiểm tra có thực hiện thành công **Common modulus attack** hay không, số liệu thu về được lưu trong `/logs/common_modulus_attack/results.csv`.

## Hướng dẫn build/run containter   
Ở thư mục gốc
```bash 
docker build -t common-modulus-lab -f docker/common-modulus-attack/Dockerfile .

docker run --rm   -v $(pwd)/logs:/logs   common-modulus-lab
```



