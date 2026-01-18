# Common Modulus Attack

Là biến thể khác của Håstad:

* Hai người dùng có **cùng modulus $n$** (do bị cấu hình sai hoặc chia sẻ cùng HSM).
* Nhưng dùng **khóa công khai khác nhau**: $e_1, e_2$
* Cùng mã hóa **chung một thông điệp $m$**.

Ta có:
$c_1 = m^{e_1} \mod n$
$c_2 = m^{e_2} \mod n$

Nếu $\gcd(e_1, e_2) = 1$(chú ý điều này thường xảy ra trong RSA nếu $e_1$ và $e_2$ khác nhau vì ta thường chọn $e$ là số nguyên tố), ta có thể dùng **Extended Euclidean Algorithm** để tìm $(a, b)$ sao cho:

$$
a e_1 + b e_2 = 1
$$

→ Khi đó:

$$
c_1^a \cdot c_2^b \equiv (m^{e_1})^{a}\cdot (m^{e_2})^{b} \equiv m^{ae_1} \cdot m^{be_2} \equiv m^{a e_1 + b e_2} \equiv m^{1} \equiv m\mod n
$$

→ Ta có thể tính được $m$ bằng cách: $m=(c_1^a \cdot c_2^b) \mod n$ 

Nếu $b < 0$, giả sử $b=-k(k>0)$, ta tính $c_2^{b} \equiv (c_2^{-1})^{k} \mod n$ (với $c_2^{-1} \mod n$ là nghịch đảo module $n$ của $c_2$)
**Kết quả:** attacker khôi phục $m$ mà không cần giải RSA.