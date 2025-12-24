# Håstad’s Broadcast Attack 
**Bối cảnh**

RSA mã hóa một thông điệp $m$ thành:

$$
c = m^e \mod n
$$

với $e$ là **public exponent** (thường nhỏ, như 3 hoặc 5)
và $n = pq$ là modulus.

Håstad’s Broadcast Attack tấn công vào điểm yếu sau: 
> Nếu e đủ nhỏ làm cho $m^e<n$ thì khi đó việc $\mod n$ trong $c=m^e \mod n$ không còn tác dụng, suy ra $m = \sqrt[e]{c}$

**Giả định:**

* Cùng một thông điệp $m$ được gửi cho **e người nhận khác nhau**
* Mỗi người có **modulus khác nhau** $n_1, n_2, \dots, n_e$
* Cùng exponent nhỏ $e$ (ví dụ $e = 3$)
* Không có padding ngẫu nhiên (số nguyên $m$ ở mỗi lần mã hóa là giống nhau)

Ta thu được:
$$
c_i = m^e \mod n_i
$$

Nếu các $n_i$ **pairwise coprime(nguyên tố cùng nhau từng đôi một, chú ý điều này rất dễ xảy ra trong RSA khi $n_i$ chỉ có hai ước nguyên tố lớn ngẫu nhiên)**, ta có thể dùng **Chinese Remainder Theorem (CRT)** để tính được $C$ với:

$$
C = m^e \pmod{N} \quad \text{với } N = n_1 n_2 \dots n_e
$$

Do $m^e < N$ vì $m < n_i \space \forall i \in [1, e]$, ta có thể lấy:
$$
m = \sqrt[e]{C}
$$
(nghĩa là căn bậc e trên số nguyên, **không modulo**).

**Kết quả:** attacker có thể khôi phục plaintext mà **không cần khóa bí mật**.