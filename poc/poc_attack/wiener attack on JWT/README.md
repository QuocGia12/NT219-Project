# Wiener Attack on JWT (RSA) – Realistic OAuth2/OIDC Lab

## 1. Giới thiệu

Đây là một **security lab mô phỏng hệ thống xác thực JWT sử dụng RSA (RS256)** theo kiến trúc **OAuth2 / OpenID Connect (OIDC)** gần với triển khai thực tế.

Lab minh họa **lỗ hổng mật mã Wiener Attack**, xảy ra khi **RSA private exponent `d` quá nhỏ**, cho phép kẻ tấn công **khôi phục private key từ public key (n, e)** và **forge JWT hợp lệ** để chiếm quyền `admin`.

**Mục tiêu học tập**
- Hiểu kiến trúc JWT + JWKS + OIDC
- Hiểu điều kiện và cơ chế của Wiener Attack
- Thực hành tấn công end-to-end:  
  **JWKS → Wiener → Rebuild RSA → Forge JWT → Bypass Authorization**

---

## 2. Kiến trúc tổng thể

### Các thành phần

| Service | Vai trò |
|------|--------|
| **auth** | Identity Provider (OIDC), phát hành JWT bằng RSA |
| **gateway** | API Gateway, xác minh JWT bằng JWKS |
| **attacker** | Khai thác Wiener Attack và forge JWT |

---

## 3. Mô tả chi tiết từng service

---

### 3.1 Auth Service (`auth/`)

**Vai trò**
- Đóng vai trò **Authorization Server / Identity Provider**
- Phát hành JWT với thuật toán **RS256**
- Công bố public key thông qua **JWKS**
- Hỗ trợ **key rotation** và **OIDC Discovery**

**Điểm yếu cố ý**
- RSA private exponent `d` được sinh **rất nhỏ (128-bit)**  
→ **Wiener vulnerable**

**Endpoints**

| Endpoint | Mô tả |
|--------|------|
| `/login` | Đăng nhập, trả JWT |
| `/.well-known/jwks.json` | Public keys (JWKS) |
| `/.well-known/openid-configuration` | OIDC discovery |

**JWT Claims**

```json
{
  "sub": "user",
  "role": ["USER"],
  "iss": "auth-service",
  "aud": "api-gateway",
  "exp": <timestamp>
}
```
### 3.2 API Gateway (Resource Server)

**Vai trò**
- Xác minh JWT bằng public key lấy từ JWKS
- Kiểm tra chữ ký RS256
- Kiểm tra `issuer`, `audience`
- Áp dụng RBAC

**Protected endpoint**
- `GET /api/admin`

**RBAC**
- Chỉ cho phép `role = admin`

### 3.3 Attacker

**Vai trò**
- Truy cập JWKS công khai
- Thực hiện Wiener Attack
- Khôi phục RSA private key `(p, q, d)`
- Forge JWT với role `admin`
- Bypass API Gateway

## 4. Wiener Attack

### Điều kiện lý thuyết

Wiener Attack thành công nếu: `d < 1/3 * n^(1/4)`

### Trong lab

- RSA modulus: 2048-bit
- Private exponent: 128-bit

→ Wiener Attack **thành công**

---

## 5. Quy trình tấn công

1. Lấy public key từ: `/.well-known/jwks.json`

2. Trích xuất `(n, e)`

3. Dùng continued fraction để tìm `d`

4. Khôi phục `(p, q)`

5. Rebuild RSA private key

6. Forge JWT hợp lệ với: `role=admin'

7. Gọi API admin thành công

---

## 6. Cách chạy lab

### 6.1 Build và khởi động hệ thống
Trong thư mục `poc/wiener-attack-on-jwt`:

```bash 
docker compose build
docker compose up
```

### 6.2 Lấy JWT hợp lệ (user thường)
```bash 
curl -X POST http://localhost:8000/login

-H "Content-Type: application/json"
-d '{"username":"user","password":"password"}'
```


### 6.3 Thực hiện tấn công Wiener

```bash 
docker compose exec attacker bash
python forge_jwt.py
```


### 6.4 Gọi API admin bằng forged JWT
```bash 
curl http://localhost:9000/api/admin

-H "Authorization: Bearer <FORGED_TOKEN>"
```
**Kết quả mong đợi:**
```
{
  "message": "FULL SYSTEM ACCESS GRANTED",
  "user": "admin"
}

```

---

## 7. Ý nghĩa bảo mật

- JWT hợp lệ về chữ ký **không đồng nghĩa an toàn**
- Public key là thông tin công khai → crypto yếu sẽ bị phá
- Một lỗi mật mã có thể phá hủy toàn bộ hệ thống IAM
- Không có RBAC hay middleware nào cứu được crypto yếu

---

## 8. Bài học thực tế

**KHÔNG BAO GIỜ**
- Tự sinh RSA key
- Dùng `d` nhỏ
- Không kiểm soát lifecycle key
- Bỏ qua audit crypto

**NÊN**
- Dùng thư viện chuẩn (OpenSSL, HSM, KMS)
- Dùng key rotation
- Giám sát bất thường JWT

---

## 9. Mục đích sử dụng

Lab chỉ phục vụ **học tập, nghiên cứu**.

**KHÔNG sử dụng vào hệ thống thực tế.**





