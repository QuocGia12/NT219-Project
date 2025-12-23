# Wiener Lab 
## Giới thiệu 
Containter thực hiện **Wiener Attack** trên các giá trị `n` và `d` từ lớn đến nhỏ, kiểm tra có thực hiện thành công **Wiener Attack** hay không, số liệu thu về được lưu trong `/logs/wiener-attack/results.csv`.

## Hướng dẫn build/run containter   
Ở thư mục gốc
```bash 
docker build -t wiener-lab -f docker/wiener-lab/Dockerfile .

docker run --rm   -v $(pwd)/logs:/logs   wiener-lab
```



