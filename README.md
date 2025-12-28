# Capstone Project — Cryptanalysis on Asymmetric Ciphers: RSA & RSA‑Based Signatures

**Subject:** NT219 - Cryptography
**Class:** NT219.Q11.ANTN
**Lecturer:** Mr. Nguyễn Ngọc Tự
**Group Infomation:**
| No. | Name | Student ID |
|:-------:|-------|:-------:|
| 1 | Nguyễn Thị Mỹ Duyên | 24520408 |
| 2 | Nguyễn Văn Quốc Gia | 24520415 |

---
## Overview
- Currently, RSA remains one of the most widely used public-key algorithms, especially in TLS/SSL protocols, key exchange, and digital signatures. The security foundation of RSA encryption is based on the computational difficulty of factoring large integers into their prime factors. For classical computers, the most efficient known algorithm for this task is the General Number Field Sieve (GNFS).
- However, this algorithm is still infeasible for keys of 2048 bits or larger. Therefore, if implemented correctly, RSA remains secure today. Nonetheless, threats to RSA are increasing. Some issues arise from implementation flaws or weak random number generators, causing many RSA keys to be compromised due to shared prime factors. In addition, side-channel attacks such as timing analysis, power consumption analysis, and electromagnetic radiation analysis can leak private keys in hardware environments.
- Furthermore, the advent of quantum computers poses a major threat to RSA. Shor’s algorithm demonstrates that if a sufficiently large and stable quantum computer exists, factoring large integers—and thus breaking RSA—could be achieved in a practical amount of time.

Therefore, understanding **the underlying concepts** and **mathematical theories behind classic attacks on RSA** helps organizations assess risks and be more cautious when deploying RSA in their projects.

## I. Basic Theory of RSA and RSA-Based Signatures

### 1. Basic Theory of RSA
RSA encryption uses two keys: a public key and a private key (corresponding to the public key).  
The public key is used for encryption and does not need to be kept secret, while the private key is used for decryption and must be kept secret.  
This means that anyone who knows the public key can encrypt information, but only the owner of the private key can decrypt the ciphertext produced with the corresponding public key.

#### Key Generation
As is traditional in cryptography literature, in this article we use Alice and Bob to represent two people who want to communicate over the internet, while Eve is the “woman-in-the-middle,” i.e., someone who can eavesdrop on their conversation.

First, Alice generates the keys as follows:
- Choose two large prime numbers $p$ and $q$
- Compute $N = p \cdot q$
- Compute $\phi(N) = (p - 1) \cdot (q - 1)$
- Choose a positive integer $e$ such that:
  - $e \in (1, \phi(N))$
  - $\gcd(e, \phi(N)) = 1$
- Compute $d$ such that $d \cdot e \equiv 1 \pmod{\phi(N)}$ (i.e., $d$ is the modular inverse of $e$ modulo $\phi(N)$)

**The public key and private key are respectively:**
- Public key: $(N, e)$
- Private key: $(N, d)$

After generating the keys, Alice sends the public key $(N, e)$ to Bob (note that Eve can read this message).

#### Encryption
Bob wants to encrypt a message $M$:
- Encode $M$ as an integer $m$
- Use the public key $(N, e)$ to compute the **ciphertext**:  
  $ct \equiv m^{e} \pmod{N}$

At this point, the message $M$ has been encrypted into $ct$. Bob sends $ct$ to Alice.

#### Decryption
Alice receives the ciphertext $ct$ and decrypts it as follows:
- Compute $m \equiv ct^{d} \pmod{N}$
- Decode $m$ back to the original message $M$

![image](https://hackmd.io/_uploads/HJ6EH86ngx.png)


##### Proof of Correctness
Here, we will prove why under the conditions in the **decryption** section:  
$$ct \equiv m^{e} \mod{N} \texttt{  implies  } m \equiv ct^{d} \mod{N}$$  

We have: $d \cdot e \equiv 1 \mod((p-1)\cdot(q-1))$  
=> $\left \{ {{d \cdot e \equiv 1 \mod{(p-1)}} \atop {d \cdot e \equiv 1 \mod(q-1)}} \right.$  

Consider $d \cdot e \equiv 1 \mod{(p-1)}$:  
=> $d \cdot e = 1 + k\cdot(p-1)$  
=> $ct^{d} = (m^{e})^{d} = m^{e \cdot d} = m^{1+k\cdot(p-1)} = m \cdot (m^{p-1})^{k} \equiv m \mod{p}$ due to Fermat’s Little Theorem ($a^{p-1} \equiv 1 \mod{p}$ when $gcd(a, p)=1$).  

Similarly, we also obtain: $ct^{d} \equiv m \mod{q}$  

By the Chinese Remainder Theorem (CRT), we conclude:  
$$
ct^{d} \equiv m \mod{(p\cdot q=N)}
$$  

### 2. RSA-Based Digital Signatures
In addition to encryption, RSA is also applied to digital signatures. The idea works similarly to encryption, but now the order of using the private key and public key is reversed.  

Suppose Alice wants to send Bob a document along with her signature. In this case, Alice keeps a private key $(N, d)$, while Bob holds the corresponding public key $(N, e)$.  

- Alice computes the hash value of the entire document she wants to send, denoted as $hash$.  
- The digital signature of the document Alice wants to send is calculated as: $sig \equiv hash^{d} \mod{N}$.  
- Alice sends the document together with the computed digital signature.  
- When Bob receives it, he computes $hash \equiv sig^{e} \mod{N}$, then calculates the hash value of the received document. If this value matches $hash$, it proves that the sender knows Alice’s private key and that the document has not been altered during transmission.
### 3. RSA Optimizations  
#### 3.1. Time Complexity Drawbacks of RSA  
Let’s consider the time complexity of computing $a^{b} \mod{N}$ where $a, b, N$ are large integers:  
- To compute the exponentiation $a^{b}$, we usually use the **square-and-multiply** algorithm with time complexity $O(\log(b))$. Note that this complexity does not yet account for the cost of integer multiplication.  
- Computing $a \cdot a \mod{N}$ can be done with various algorithms, but the most efficient known complexity is about $O(n\log(n))$, where $n$ is the bit length of $N$. Since $N$ is a large integer, $n$ is also large.  

Thus, the overall time complexity of computing $a^{b}$ is $O(\log(b) \cdot n\log(n))$, where $n$ is the bit length of $a$.  

We often choose $e = 65537 = 2^{16}+1$ because:  
- $e$ still satisfies the property $1 < e < N$ and $gcd(e, \phi(N)) = 1$. (Note that $65537$ is a prime number, so we only need to ensure that $65537 \nmid (p-1)$ and $65537 \nmid (q-1)$ when choosing $p$ and $q$).  
- $\log(65537) \approx 5$, which is very small.  

Therefore, the encryption step (computing $m^{e} \mod{N}$) is very fast, which explains why $e=65537$ is commonly chosen.  

However, when it comes to decryption, we must consider the following:  
- $d$ is not chosen beforehand but is instead dependent on $e=65537$ and $\phi(N) = (p-1)\cdot(q-1)$, since $d \equiv e^{-1} \mod{\phi(N)}$.  
- Because of this, $d$ is usually very large, with $d \approx \phi(N) = p \cdot q - p - q + 1 \approx N$.  

As a result, the decryption time in RSA is often quite large, which motivates the introduction of **RSA-CRT**.  

#### 3.2. RSA-CRT  
RSA-CRT applies the Chinese Remainder Theorem (CRT) to optimize decryption time, specifically as follows:  
- **Key generation**:  
  - Compute $d_{p} \equiv e^{-1} \mod (p-1)$  
  - Compute $d_{q} \equiv e^{-1} \mod (q-1)$  
- **Encryption**: Same as standard RSA, $ct \equiv m^{e} \mod{N}$  
- **Decryption**:  
  - Compute $m_p \equiv ct^{d_{p}} \mod{p}$  
  - Compute $m_q \equiv ct^{d_{q}} \mod{q}$  
  - Solve the following system of congruences using CRT:  
    - $\left \{ {{m \equiv m_p \mod{p}} \atop {m \equiv m_q \mod{q}}} \right.$  
  - The solution $m \mod (p\cdot q = N)$ is the plaintext.  

**Analyzing the time complexity of RSA-CRT:** RSA-CRT splits decryption into two computations of the form $a^{b} \mod{M}$, but in each case the modulus $M$ is much smaller compared to the single computation in standard RSA (since $d_p \approx p \approx \sqrt{N}$).  

However, implementing RSA-CRT requires careful consideration because it may introduce certain security weaknesses that attackers can exploit. These issues will be discussed further in the section **Fault Attacks on RSA-CRT**.  

### 4. The Core Problem in RSA
The fundamental problem in RSA is:  
> Solve the hidden congruence equation for $x$:  
$$
x^{e} \equiv ct \mod{N}
$$  
where $N$ is the product of two prime numbers and $gcd(e, \phi(N))=1$.  

To **completely** **break** RSA, one needs to solve the above problem in a practical amount of time.  
Currently, the most efficient method to solve it is to factorize the large integer $N$ (in RSA, this is the modulus). If we can factorize $N$, we obtain $p$ and $q$, and then compute $\phi(N) = (p-1)\cdot(q-1)$. From this, the private key can be derived: $d \equiv e^{-1} \mod{\phi(N)}$. Once $d$ is known, the solution to the equation is simply:  
$$
x = ct^{d} \mod{N}
$$  

***Therefore***: Keeping $p$ and $q$ secret is fundamental in RSA encryption—this is just as important as keeping $d$ secret. Many cryptographic attacks on RSA focus on recovering $p$ and $q$.
## II. Các class attack phổ biến 
### 1. Factoring 
> Lớp tấn công này dựa trên một ý tưởng rất tự nhiên rằng tìm một thuật toán mạnh để factoring số nguyên lớn $N$. 

Hiện nay có nhiều thuật toán dùng để factoring N ra đời, một trong những ý tưởng được sử dụng nhiều là: 
> Tìm hai số nguyên $a$ và $b$ thỏa mãn $a^2 \equiv b^2 \mod N$ và $a \ne \pm b \mod N$

Khi tìm được hai số nguyên thỏa mãn như thế: 
→ $a^2-b^2=kN$
→ $(a-b)(a+b)=kN$
Do $p$ là một trong hai ước nguyên tố của $N$ → $(a-b)$ chia hết cho $p$ hoặc $(a+b)$ chia hết cho $p$ 
Chú ý điều kiện $a \ne \pm b \mod N$ nên thừa số chia hết cho $p$ đó sẽ không chia hết cho $q$
→ $p=gcd(a-b, N)$ hoặc $p=gcd(a+b, N)$
→ Factoring $N$ thành công 

Một trong những thuật toán sử dụng ý tưởng trên là thuật toán **GNFS**, là thuật toán nhanh nhất ở hiện tại dùng để factoring số nguyên lớn $N$(dạng tổng quát) với độ phức tạp:
$$
\quad
L_N\left[\frac{1}{3}, \left(\frac{64}{9}\right)^{1/3}\right] 
= \exp \Bigg( \big((64/9)^{1/3} + o(1)\big) (\ln N)^{1/3} (\ln \ln N)^{2/3} \Bigg)
$$ 

Với thuật toán này, số nguyên $N$ $512$ bits có thể bị factoring chỉ trong vài giờ, số nguyên $N$ $1024$ bits thì bị factoring trong nhiều năm. Hiện nay, nhiều hệ thống sử dụng RSA $2048$ bits. Tuy nhiên, với khả năng về sự xuất hiện máy tính lượng tử trong nhiều năm tới thì khuyến nghị cần phải sử dụng $RSA$ $3072$ bits để an toàn.

Thuật toán Shor là một thuật toán lượng tử giúp phân tích nhân tử một số nguyên ở dạng $N = p.q$, với $p$ và $q$ là các số nguyên tố. Trong lý thuyết thì nếu đủ qubit thì bất kì RSA nào cũng có thể bị phá bằng thuật toán Shor này.

### 2. Key generation weakness
> Lớp tấn công này nhắm vào những trường hợp đặc biệt của key 
#### 2.1. Wiener (1990) on small private exponent attack.

##### Nhắc lại công thức RSA

RSA có: 
* $( n = p \cdot q )$
* $( \varphi(n) = (p-1)(q-1) )$
* $( e \cdot d \equiv 1 \pmod{\varphi(n)} )$

Nghĩa là: $e \cdot d = 1 + k\varphi(n)$,  với $k$ là số nguyên dương.

##### Khi d quá nhỏ

Nếu d nhỏ, tức là: $d < n^{0.25} / 3$ thì **Wiener (1990)** chứng minh rằng có thể **tính lại d** từ **(e, n)** bằng **[phân số liên tục (continued fractions)](https://vi.wikipedia.org/wiki/Li%C3%AAn_ph%C3%A2n_s%E1%BB%91)**.

Ý tưởng là:

* Do $( e \cdot d - k\varphi(n) = 1 )$, nên:
$$
  \frac{e}{n} \approx \frac{k}{d}
$$
* Từ đó, kẻ tấn công có thể dùng **phân số liên tục (continued fraction)** để tìm xấp xỉ của $e/n$, thử các cặp $(k_i, d_i)$ để tìm ra $d$ thật sự.

##### Hậu quả

Nếu tìm được $d$, thì:

* Kẻ tấn công **giải mã được mọi ciphertext**: $m = c^d \bmod n$
* Hoặc **ký giả mạo** các thông điệp RSA-signature hợp lệ.


##### Nguyên nhân thực tế có thể dẫn đến “d nhỏ”

* Hệ thống cố ý chọn $d$ nhỏ để **tăng tốc giải mã** (vì giải mã = $c^d \mod n$ ).
* Hoặc chọn $e$ quá lớn → khiến $d$ nhỏ do $e \cdot d ≡ 1 \pmod{\varphi(n)}$.


##### Biện pháp phòng tránh

* Không bao giờ chọn $d < n^{0.25}$.
* Thực tế, hầu hết các hệ thống dùng:

  * $e = 65537$
  * $d$ ngẫu nhiên đủ lớn (vì được sinh tự động từ hàm inverse mod).
* Hoặc dùng **RSA-CRT**, **RSASSA-PSS** để cải thiện tốc độ mà vẫn an toàn.


<!-- Nếu $d$ thực sự nhỏ (thỏa điều kiện Wiener), thì có thể **phục hồi được d trong vài giây**.

---

**Tóm lại:**

> Khi $d$ nhỏ, RSA không còn an toàn — có thể bị tấn công bằng Wiener’s Attack vì mối quan hệ tuyến tính giữa $e/n$ và $k/d$. -->

---

#### 2.2. Håstad’s attack on low exponents and common modulus scenarios

##### Bối cảnh

RSA mã hóa một thông điệp $m$ thành:

$$
c = m^e \mod n
$$

với $e$ là **public exponent** (thường nhỏ, như 3 hoặc 5)
và $n = pq$ là modulus.

Håstad’s Broadcast Attack tấn công vào điểm yếu sau: 
> Nếu e đủ nhỏ làm cho $m^e<n$ thì khi đó việc $\mod n$ trong $c=m^e \mod n$ không còn tác dụng, suy ra $m = \sqrt[e]{c}$

##### Håstad’s Broadcast Attack (1985)

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

##### Common Modulus Attack

Là biến thể khác của Håstad:

* Hai người dùng có **cùng modulus $n$** (do bị cấu hình sai hoặc chia sẻ cùng HSM).
* Nhưng dùng **khóa công khai khác nhau**: $e_1, e_2$
* Cùng mã hóa **chung một thông điệp $m$**.

Ta có:
$c_1 = m^{e_1} \mod n$
$c_2 = m^{e_2} \mod n$

Nếu $\gcd(e_1, e_2) = 1$(chú ý điều này thường xảy ra nếu $e_1$ và $e_2$ khác nhau vì ta thường chọn $e$ là số nguyên tố), ta có thể dùng **Extended Euclidean Algorithm** để tìm $(a, b)$ sao cho:

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

##### Biện pháp phòng tránh

* **Không dùng RSA raw**, luôn thêm padding ngẫu nhiên như **OAEP**:
    - Khi đó $m$ được tăng lên gần với $n$, hạn chế hoàn toàn khả năng $m^e<n$. 
    - Đồng thời khi đó mặc dù plaintext giống nhau nhưng số nguyên $m$ tương ứng ở mỗi lần mã hóa là khác nhau. 
* Không dùng chung modulus giữa nhiều người.
* Dùng **exponent đủ lớn**.

---

### 3. Implementation Attack 
> Lớp tấn công này này không tấn công trực tiếp vào tính toán học của RSA, thay vào đó nó nhắm vào những lỗi triển khai có thể xảy ra 

#### 3.1. Bleichenbacher on PKCS#1 v1.5 padding oracle attack

##### Tổng quan ngắn

Bleichenbacher (1998) là cuộc tấn công **adaptive chosen-ciphertext** nhắm vào chuẩn **PKCS#1 v1.5** của RSA.
Điểm mấu chốt không nằm ở toán học phức tạp, mà ở việc:

> **Hệ thống vô tình để lộ thông tin “padding có hợp lệ hay không” sau khi giải mã RSA.**

Chỉ với một phản hồi **Yes / No** (hoặc tương đương), attacker có thể:

* Gửi nhiều ciphertext được “biến hình” từ ciphertext gốc.
* Quan sát phản hồi của server.
* Từng bước **thu hẹp không gian giá trị của plaintext**.
* Cuối cùng **khôi phục hoàn toàn message gốc** (ví dụ: session secret trong TLS).

Điều này có nghĩa là:

* RSA **vẫn đúng về mặt toán học**,
* Nhưng **PKCS#1 v1.5 + xử lý lỗi không an toàn** khiến RSA **mất hoàn toàn tính bảo mật** trong kịch bản thực tế.


##### Bản chất lỗ hổng của PKCS#1 v1.5 

PKCS#1 v1.5 định nghĩa một cấu trúc padding rất cứng nhắc:

```
0x00 || 0x02 || PS || 0x00 || D
```

Vấn đề nằm ở chỗ:

- Sau khi RSA-decrypt, hệ thống **bắt buộc phải kiểm tra padding**.
- Quá trình kiểm tra này thường:
  - Trả về **lỗi khác nhau** (explicit error),
  - Hoặc **thời gian xử lý khác nhau** (implicit error).
Chỉ cần attacker phân biệt được:
- “Padding đúng” vs “Padding sai”
  → hệ thống đã trở thành **padding oracle**.

##### Vì sao Bleichenbacher nguy hiểm trong triển khai RSA?

Bleichenbacher không phá RSA trực tiếp, nhưng:
- Cho phép **giải mã dữ liệu mà attacker không được phép giải mã**.
- Đặc biệt nguy hiểm với:
  - TLS handshake (Pre-Master Secret).
  - Session keys (16–32 bytes).
  - Token, API secrets.

Trong thực tế:
- Không cần tấn công toàn bộ message,
- Chỉ cần lấy được **session key**, attacker có thể giải mã toàn bộ traffic đối xứng phía sau.

Nhiều hệ thống từng vá lỗi bằng cách giấu thông báo lỗi hay thay đổi message trả về. Nhưng điều này **không đủ**, vì oracle **có thể tồn tại gián tiếp** (ví dụ qua timing).

##### Ý nghĩa thực tiễn

Bleichenbacher chỉ ra một bài học quan trọng:

> **RSA không an toàn nếu padding không được thiết kế để chống chosen-ciphertext attack.**

Chuẩn PKCS#1 v1.5:

- Không có cơ chế ngẫu nhiên đủ mạnh để che đi cấu trúc plaintext.
- Không đảm bảo an toàn trong mô hình CCA.
- Và **không thể sửa triệt để chỉ bằng vá lỗi triển khai**.

##### Áp dụng vào chữ ký số

Nếu cùng một logic kiểm tra “PKCS conforming” được dùng cho:
- RSA decryption
- hoặc RSA signature verification.

thì attacker có thể:

* Dùng oracle để suy ra giá trị liên quan đến $m^d$,
* Dẫn đến **giả mạo chữ ký** trong một số kịch bản triển khai sai.

##### Giải pháp

1. **Ngưng sử dụng PKCS#1 v1.5 cho mã hóa**:  Dùng **RSA-OAEP** (được chứng minh an toàn trong mô hình CCA).
2. **Đối với chữ ký**: Dùng **RSA-PSS** thay vì v1.5.
3. **Triển khai an toàn**
   - Constant-time xử lý.
   - Không phân biệt lỗi.
   - Không để lộ bất kỳ oracle nào (kể cả gián tiếp).

#### 3.2. Marvin’s Attack

##### Tổng quan

Marvin’s Attack (được công bố và khai thác thực tế nhiều năm sau Bleichenbacher) cho thấy rằng:

> **Ngay cả khi hệ thống không trả về oracle rõ ràng, RSA với PKCS#1 v1.5 vẫn có thể bị phá thông qua side-channel timing.**

Nói cách khác:

* Bleichenbacher cần **explicit oracle** (error message),
* Marvin’s Attack tạo ra **implicit oracle** từ **thời gian phản hồi**.

##### Bản chất của Marvin’s Attack

Trong nhiều triển khai RSA:

* Padding đúng → hệ thống tiếp tục xử lý (sinh key, handshake, HMAC, …),
* Padding sai → hệ thống dừng sớm.

Sự khác biệt này dẫn đến:

* **Chênh lệch thời gian xử lý có thể đo được**,
* Dù không có bất kỳ thông báo lỗi nào trả về cho attacker.

Marvin’s Attack biến:

```
Thời gian phản hồi  →  Padding đúng / sai
```

và từ đó:

* Xây dựng lại **padding oracle**,
* Áp dụng lại toàn bộ logic của Bleichenbacher.

##### Vì sao Marvin’s Attack đặc biệt nguy hiểm?

* Phá vỡ giả định “đã giấu error là an toàn”,
* Tấn công được cả những hệ thống:

  * Chỉ trả về một message chung chung,
  * Không log lỗi,
  * Không phân biệt trạng thái ở mức giao thức.

Điều này cho thấy:

> **Side-channel là một phần của oracle**, không phải ngoại lệ.

##### Ý nghĩa đối với triển khai RSA hiện đại

Marvin’s Attack khẳng định rằng:

* PKCS#1 v1.5 **không thể dùng an toàn**, kể cả khi “triển khai cẩn thận”,
* Các vá kiểu:

  * Delay ngẫu nhiên
  * Che lỗi thủ công
  * Log ẩn

đều **không đủ mạnh** trước attacker có khả năng đo thời gian chính xác.


##### Kết luận cho Padding Oracle
- Error hiding không đồng nghĩa với an toàn.
- RSA PKCS#1 v1.5 không thể bảo vệ khỏi side-channel ở tầng triển khai.
- Constant-time không phải là tùy chọn, mà là bắt buộc.

**Giải pháp:**

- Chuyển sang RSA-OAEP (chống CCA theo thiết kế).
- Triển khai giải mã constant-time tuyệt đối.
- Không sử dụng RSA để mã hóa session key trong giao thức mới.
- Ưu tiên (EC)DHE trong TLS hiện đại.

#### 3.3. RSA-CRT Fault Attack 
##### Nhắc lại RSA-CRT 
Như đã nói ở phần trên, RSA-CRT thường được áp dụng để giảm thời gian giải mã hoặc ký so với RSA mặc định: 
- **Key generation**:  
  - Compute $d_{p} \equiv e^{-1} \mod (p-1)$  
  - Compute $d_{q} \equiv e^{-1} \mod (q-1)$  
- **Signature Generation**:  
  - Compute $S_p \equiv h^{d_{p}} \mod{p}$  
  - Compute $S_q \equiv h^{d_{q}} \mod{q}$  
  - Solve the following system of congruences using CRT:  
    - $\left \{ {{S \equiv S_p \mod{p}} \atop {S \equiv S_q \mod{q}}} \right.$  
  - The solution $S \mod (p\cdot q = N)$ is the Signature.

##### Ý tưởng tấn công 
Có nhiều loại Fault Attack tấn công vào các hệ thống nhúng như là smart cards, một trong số đó là Fault Attack của Boneh-DeMillo-Lipton: 
- Nếu như có Attacker có thể gây lỗi xảy ra ở chỉ một trong hai lần việc tính $S_p \equiv h^{d_{p}} \mod{p}$ hoặc $S_q \equiv h^{d_{q}} \mod{q}$, giả sử lỗi xảy ra ở $S_p$, kết quả tính được là $S'_p \ne S_p \mod n$.
- Khi đó, sử dụng CRT để giải hệ phương trình:  $\left \{ {{S' \equiv S'_p \mod{p}} \atop {S' \equiv S_q \mod{q}}} \right.$ 
    - Signature tính được gọi là $S'$, nhận xét: 
        - $S' \ne S \mod p$
        - $S' \equiv S \mod q$
    - Suy ra, $S'-S$ chia hết cho $q$ và không chia hết cho $p$
- Suy ra: $gcd(S'-S, N)=q$, như vậy ta có thể phân tích thừa số nguyên tố của $N$ 

Trong thực tế, Attacker có nhiều cách để gây lỗi trên các hệ thống nhúng như giả thuyết trên: 
- Variations in Suply Voltage 
- Variations in the external clock 
- Temperature Variation 
- White light
- ... 
##### Giải pháp 
Một giải pháp đơn giản nhưng hiệu quả để chống lại Boneh-DeMillo-Liton Fault Attack là **Verify After Sign**: Sau khi tính được chữ ký $S$, kiểm tra $S^e \equiv h \mod N$, nếu đúng thì mới trả về $S$

Thực tế có nhiều loại Fault Attack tấn công trên RSA-CRT và muốn an toàn thì cần kết hợp nhiều giải pháp lại với nhau chứ không chỉ thực hiện mỗi **Verify After Sign**
#### 3.4. Timing Attack on RSA 
##### Ý tưởng tấn công 
Timing Attack tấn công vào thuật toán **Square and Multiply**(dùng để tính lũy thừa module $a^b \mod N$)
Mã giả của thuật toán **Square and Multiply** dùng để tính $h^d\mod n$: 
```python
# Mã giả 
Square_and_Multiply(h, d, n){
    res = 1
    Duyệt các bit x của d, trọng số thấp đến cao: 
        if x == 1: 
            res=res*h 
        h*=h 
    return res 
}
```
→ Nhận xét: nếu bit đang xét của $d$ là 1 thì trong lần lặp đó thực hiện 2 phép nhân, ngược lại nếu bit đang xét của $d$ là 0 thì chỉ thực hiện 1 phép nhân 
→ Attacker có thể đo thời gian để lần lượt đoán các bits của $d$ từ trọng số thấp đến cao, từ đó đoán được giá trị của $d$
##### Giải pháp 
**a. Constant time** 
Thay đổi một phần thuật toán **Square-and-Multiply** sao cho dù bit đang xét là 1 hay là 0 thì nó vẫn thực hiện số phép tính như nhau và dùng mask để chọn kết quả mong muốn trả về 
Ví dụ: 
```python 
# Mã giả 
Square_and_Multiply_ConstantTime(h, d, n):
    res=1
    Duyệt các bit x của d, trọng số thấp đến cao: 
        tmp1=res 
        tmp2=res*h
        h*=h 
        res=tmp2*(1-x)+tmp1 
    return res
```
→ Nhận xét trong mã giả trên, các phép tính được thực hiện là như nhau dù cho bit `x` đang xét là 0 hay là 1 và cũng không sử dụng if else để chọn giá trị trả về → Về mặt lý thuyết thì mã giả trên đã tính được $h^d \mod n$ constant time  

**b. RSA-Blinding**
Thay vì tính $m=c^d\mod n$ một cách trực tiếp, ta áp dụng **RSA-Blinding** như sau:
- Tính $c'=c \cdot r^e \mod n$ với $r$ là một giá trị bất kì thỏa $gcd(r, n)=1$
- Tính $m'=(c')^d=(c\cdot r^e)^d =c^d \cdot r=m \cdot r \mod n$
- Tính $m=m' \cdot r^{-1} \mod n$

→ Bây giờ, thời gian tính $m=c^d\mod n$ phụ thuộc vào $r$, một giá trị random, khi đó Attacker khó có thể đoán được các bit của $d$ từ việc đo thời gian

---


## III. Methodology 
Phần này chúng tôi triển khai một số tấn công chính của các nhóm lỗi trên trên môi trường mô phỏng lỗi. Từ đó rút ra các nhận xét trên các tấn công này. 

|No.    |Attack    |Link PoC|
|:---:    |---    |---|
|1      |Bleichenbacher Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/bleichenbacher_attack|
|2      |Marvin Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/marvin_attack|
|3      |Common Modulus Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/common_modulus_attack|
|4      |Hastad Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/hastad_attack|
|5      |Wiener Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/wiener_attack|
|6 |RSA-CRT Fault Attack|https://github.com/QuocGia12/NT219-Project/tree/main/poc/RSA_CRT_fault_attack|

---

## IV. Deep Deployment Weakness Analysis
### 1. TLS 
TLS Handshake là bược thiết lập quan trọng cho một kết nối an toàn giữa client và server. Trong quá trình này, cả hai bên đồng ý về phiên bản TLS, cipher suite, xác thực server và tạo ra session key để mã hóa dữ liệu trong phiên đó.  
![image](https://hackmd.io/_uploads/SyWC9JdZbx.png)
Các bước cơ bản trong quá trình TLS Handshake:
- Client gửi message ClientHello đến server, message này gồm các phiên bản TLS mà Client hỗ trợ, danh sách các loại mã hóa mà Client hỗ trợ, cùng với một số ngẫu nhiên ClientRandom
- Server gửi lại message ServerHello, message này chứa phiên bản TLS, loại mã hóa mà Server chọn trong danh sách gửi từ Client. Đồng thời cũng gồm Certificate của Server. 
    - Certificate của Server dùng để xác thực Server cũng như chứa Public Key, Public Key này dùng để xác thực dữ liệu mà Server ký, từ đó Attacker không thể giả mạo server cũng như không thể thực hiện Man-in-the-Middle Attack 
- Trao đổi khóa: Server và Client gửi cho nhau các tham số sử dụng trong loại mã hóa đã chọn, từ đó cả hai tính được PreMasterSecret. Sử dụng PreMasterSecret cùng với ClientRandom và ServerRandom, Client và Server tính MasterSecret, tức là Session Key. Toàn bộ dữ liệu trong phiên này sẽ được mã hóa bởi Session Key đó. 
 
> Chú ý một điều quan trọng là TLS 1.3 không còn sử dụng trao đổi khóa RSA nữa mà thay vào đó chỉ sử dụng ECDHE 

#### Những weeknesses về RSA trong TLS 1.2
##### a. Không forward secrecy 
Chú ý trong TLS 1.2, các tham số $(n, e, d)$ sử dụng trong mã hóa RSA cũng chính là các tham số $(n, e, d)$ trong Certificate của Server, vì thế nếu như Server không thay đổi Certificate thì các tham số $(n, e, d)$ mà Server sử dụng trong các phiên khác nhau là như nhau. Dẫn đến nếu như Attacker lấy được $d$ thì Attacker có thể giải mã được toàn bộ các phiên sử dụng trao đổi khóa RSA. → Không có tính forward secrecy 

→ Vì thế trong TLS 1.3 đã loại bỏ hoàn toàn trao đổi khóa RSA, thay vào đó chỉ sử dụng ECDHE. Từ đó nếu Attacker có thể tấn công một phiên thì vẫn không giải mã được các phiên khác, vì thế đảm bảo tính forward secrecy 

##### b. Kịch bản Bleichenbacher Attack khi hệ thống hỗ trợ TLS 1.2, không hỗ trợ TLS 1.3 
- Attacker thực hiện Man-in-the-Middle Attack, thay đổi message ClientHello của Client sao cho danh sách Cipher Suite chỉ gồm RSA, ép Server phải chọn Cipher Suite là RSA. 
- Sau đó, Attacker chặn gói tin ClientKeyExchange từ Client, xem Server là một oracle để thực hiện Bleichenbacher's Attack. Nếu như Server để lộ sự khác biệt thời gian về kết quả padding thì Attacker có thể lấy được PreMasterSecret, từ đó tính được Session Key, giải mã được toàn bộ gói tin gửi trong phiên đó. 

Chú ý kịch bản tấn công này không thể sử dụng trong TLS 1.3 vì: 
- Trong TLS 1.3, không hỗ trợ trao đổi khóa RSA 
- Trong TLS 1.3, Server ký toàn bộ transript trong quá trình bắt tay, sau đó gửi cho Client để Client xác nhận lại. Vì thế Attacker không thể thay đổi bất cứ điều gì trong quá trình bắt tay. 

---

### 2. JWT / token signing (RS256)
JWT - JSON Web Token là một chuỗi dùng để xác thực Authentication và Authorization của một user. 

`JWT = <base64-encoded header>.<base64-encoded payload>.<base64-encoded signature>`
- `header`: chứa thuật toán ký, ví dụ `"alg": "..."`
- `payload`: thông tin dùng để xác thực Authentication và Authorization của user
- `signature`: chữ ký của `header + payload`, bảo vệ tính toàn vẹn của `header` và `payload`

Thuật toán ký sử dụng có thể chia làm 2 phần: 
- HMAC → issuer và verifier cần chia sẻ với nhau trước secret key. Ví dụ: `HS256`(HMAC with SHA-256)
- Chữ ký số → ký bằng private key, verify bằng public key. Ví dụ: `RS256`(RSA with SHA-256)

Nếu như Server cấu hình việc Verify **không xác định rõ thuật toán verify mà tin vào `alg` của JWT từ client** thì có thể dẫn đến Token forgery: 

**Kịch bản 1:** 
Attacker tạo JWT giả mạo, gán `"alg": "None"`, `JWT = <base64-encoded header>.<base64-encoded payload>.` → Nếu như Server vẫn tin vào `"alg": "None"` mà verify hợp lệ thì attacker có thể tạo bất kì JWT hợp lệ. 
→ cần từ chối `"alg": "None"`
**Kịch bản 2:**
Server sử dụng `"alg" = "RS256"` để ký nhưng khi verify lại không kiểm tra chặt điều kiện `"alg" = "RS256"`, tin JWT của client. 
```py
# Pseudo-code:
def verify(token):
    header = parse_header(token)
    key = load_key()  # RSA public key

    if header["alg"] == "RS256":
        return rsa_verify(token, key)
    elif header["alg"] == "HS256":
        return hmac_verify(token, key)
```

Chú ý khi Server sử dụng `"alg" = "RS256"` thì Server verify bằng public key(public)
→ Attacker tạo một JWT giả mạo theo ý muốn rồi gán `alg = HS256`, ký bằng `HS256` với secret key sử dụng là public key. 
→ Server verify bằng **HS256** hợp lệ. 
→ Yêu cầu: cần phải xác định rõ `alg` khi verify 


---

### 3. Code signing & package ecosystems (D - check)
#### a. Key exposure
**Phân tích:** Môi trường CI/CD (DevOps) thường là mắt xích yếu nhất. Nếu private key được lưu dưới dạng file (ví dụ: `.pem`) trong code repo hoặc biến môi trường không được mã hóa, kẻ tấn công xâm nhập được vào build server sẽ copy được key này.
**Tác động:** Kẻ tấn công có thể tự ký (self-sign) các token hợp lệ (Forged Tokens) với bất kỳ quyền hạn nào (Admin privilege escalation). Đây là kịch bản "Golden Token".
**Khắc phục:** Không bao giờ lưu private key trên đĩa cứng của server ứng dụng. Sử dụng **HSM (Hardware Security Module)** hoặc các dịch vụ quản lý khóa đám mây (như AWS KMS, Azure Key Vault) để thực hiện thao tác ký. Private key không bao giờ rời khỏi thiết bị bảo mật.
#### b. Legacy signature format: 
Legacy signature format là các lược đồ hoặc định dạng chữ ký lỗi thời cho phép một message có thể có nhiều chữ ký hợp lệ khác nhau, dù được ký bằng cùng một private key.
Bên cạnh đó, từ một chữ ký hợp lệ cũng có thể tính được một chữ ký hợp lệ khác tương ứng với message đó một cách dễ dàng. 
→ **Signature malleability**: message không thay đổi, chữ ký thay đổi nhưng khi verify vẫn hợp lệ. 

Trong thực tế, nhiều hệ thống cần gán một hành động với một ID để ngăn chặn Attacker thực hiện Replay Attack. Trước khi thực hiện một hành động, kiểm tra ID đó tồn tại chưa rồi mới thực hiện. 
Nếu như hệ thống sử dụng chữ ký số làm ID, Attacker có thể tính một chữ ký hợp lệ khác tương ứng với hành động đó(Signature malleability) rồi thực hiện Replay Attack. 

→ Cần tách biệt chữ ký với ID: 
- Signature: kiểm tra tính toàn vẹn và xác thực nguồn gốc của message 
- ID: định danh hành động(thường dùng một số random Nonce)

Bên cạnh đó, signature cần ký luôn cả ID 
Để chống **Signature malleability**, chỉ xác thực chữ ký ở một format nhất định, không verify hợp lệ những chữ ký ở format khác. 


---

### 4. Smartcards / HSMs / TPMs

Khi RSA được đẩy xuống phần cứng, các vector tấn công chuyển từ phần mềm sang vật lý và API.

* **Side‑channel & Fault attacks:**
    * **Phân tích:**
        * **Power Analysis (DPA/SPA):** Khi chip thực hiện tính toán RSA, lượng điện năng tiêu thụ thay đổi tùy thuộc vào việc nó đang xử lý bit 0 hay bit 1 của khóa bí mật. Kẻ tấn công đo đạc dao động điện năng này để tái tạo lại chuỗi bit của private key.
        * **Fault Injection (RSA-CRT):** Kẻ tấn công sử dụng tia laser hoặc dao động điện áp để gây lỗi trong quá trình tính toán CRT (Chinese Remainder Theorem). Chỉ cần 1 lỗi tính toán duy nhất cũng đủ để lộ hoàn toàn một thừa số nguyên tố ($p$ hoặc $q$).
    * **Khắc phục:** Sử dụng smartcard đạt chuẩn FIPS 140-2 Level 3+ có lớp bảo vệ vật lý (mesh shield). Về thuật toán, luôn thực hiện verify chữ ký ngay trên chip trước khi xuất kết quả ra ngoài. Nếu verify sai, không trả về kết quả lỗi (để tránh lộ manh mối) mà hủy phiên làm việc.

* **API misuse (PKCS#11 attacks):**
    * **Phân tích:** HSM thường giao tiếp qua chuẩn PKCS#11. Nếu API không được phân quyền chặt (ACL), một ứng dụng bị xâm nhập có thể yêu cầu HSM giải mã bất cứ thứ gì.
    * **Bleichenbacher Oracle via HSM:** Nếu HSM trả về các mã lỗi khác nhau cho "sai khóa" và "sai padding" khi giải mã RSA, kẻ tấn công có thể lợi dụng HSM như một Oracle để giải mã tin nhắn mà không cần trích xuất private key.
    * **Khắc phục:** Áp dụng **Key Wrapping** (chỉ cho phép dùng key này để wrap key khác, không cho phép decrypt dữ liệu thô). Giới hạn quyền sử dụng key (Usage Flags) chỉ cho phép `Sign` hoặc `Decrypt` cụ thể, không được bật cả hai cho cùng một key.

---

### 5. Random Number Generator-RNG 
Là công cụ dùng để tạo số ngẫu nhiên không thể dự đoán. 
Phân loại: 
- **TRNG(True Random Number Generator)**: tạo số ngẫu nhiên thực sự dựa vào hiện tượng vật lý không thể dự đoán: 
    - Avalanche diodes (Zener breakdown noise), reverse biased
    - Atmospheric noise (via attached radio-receiver)
    - Thermal noise in resistor (amplified)
    - Radioactive decay etc.

    → Dùng để tạo **entropy**(hay **seed**) dùng trong PRNG 
- **PRNG(Pseudo Random Number Generator)**: thuật toán tạo ra một số ngẫu nhiên từ seed 

→ Một RNG tốt, được dùng trong mật mã cần TRNG sinh seed có entropy cao và PRNG tốt( không thể tính input từ output, không có mối liên hệ giữa input và output)
#### Sử dụng RNG trong RSA 

Trong RSA, RNG được dùng để tạo số nguyên tố $p$ và $q$ ngẫu nhiên. 

Nếu như, RNG sinh số không đủ ngẫu nhiên, thừa số nguyên tố $p$ có thể bị trùng trong hai modulo $n1$ và $n2$ khác nhau, từ đó tính được $p=gcd(n1, n2)$

Lý do RNG không sinh số ngẫu nhiên tốt đa số là do thiết bị không sử dụng TRNG hoặc sử dụng TRNG lấy nguồn entrophy kém. Bên cạnh đó, cũng có thể do việc không sử dụng PRNG theo chuẩn NIST mà thay vào đó lại sử dụng PRNG tự chế.

→ Yêu cầu: cần sử dụng RNG chất lượng cao và sử dụng PRNG theo chuẩn của NIST như: 
- Hash_DRBG (SHA-256, SHA-512)
- HMAC_DRBG
- AES-CTR-DRBG
- ChaCha20-DRBG (libsodium, Linux /dev/urandom)

Nếu được thì sử dụng HSM / TPM khi có thể.

---

### 6. Implementation bugs & side channels

Đây là lớp rủi ro liên quan đến việc lập trình thuật toán RSA trong các thư viện (OpenSSL, Bouncy Castle, v.v.) hoặc custom code.
Phần này được trình bày rõ trong phần **4. Implementation Attack** của **phần II**, ở dưới sẽ tóm tắt lại các chi tiết quan trọng. 

* **Timing leaks in modular exponentiation:**
    * **Phân tích:** Phép tính mũ $m^d \pmod n$ thường dùng thuật toán "Square-and-Multiply". Nếu bit của $d$ là 1, CPU thực hiện thêm phép nhân; nếu là 0 thì không. Sự chênh lệch thời gian này (dù chỉ vài micro giây) qua mạng LAN hoặc internet đủ để kẻ tấn công thống kê và tìm ra $d$.
    * **Khắc phục:** 
        * Bắt buộc sử dụng cài đặt **Constant-time** (thời gian thực thi không phụ thuộc vào dữ liệu đầu vào). 
        * Sử dụng kỹ thuật **Blinding**: Nhân dữ liệu đầu vào với một số ngẫu nhiên trước khi tính toán, sau đó loại bỏ nó, làm cho kẻ tấn công không thể đoán được trạng thái bên trong.

* **CRT recombination faults (The Bellcore Attack):**
    * **Công thức:** RSA-CRT tính chữ ký $S$ bằng cách tính $S_p = M^d \pmod p$ và $S_q = M^d \pmod q$. Nếu lỗi xảy ra khi tính $S_p$ (tạo ra $S'_p$) nhưng $S_q$ đúng, chữ ký sai $S'$ sẽ được tạo ra.
    * **Khai thác:** Kẻ tấn công tính ước chung lớn nhất: $$\gcd(S - S', N) = q$$
    * **Kết quả:** Lập tức tìm ra thừa số nguyên tố $q$, từ đó suy ra $p$ và phá vỡ hoàn toàn RSA.
    * **Khắc phục:** Luôn luôn kiểm tra lại kết quả tính toán: $S^e \equiv M \pmod N$ trước khi trả về $S$.

* **Padding oracle in TLS stacks (Bleichenbacher/ROBOT):**
    * **Phân tích:** Trong RSA PKCS#1 v1.5 (dùng cho trao đổi khóa TLS cũ), cấu trúc bản rõ phải bắt đầu bằng `00 02`. Nếu server phản hồi nhanh hơn hoặc trả về thông báo lỗi khác nhau khi giải mã một gói tin không đúng định dạng `00 02`, nó tạo ra một "Padding Oracle".
    * **Tác động:** Kẻ tấn công gửi hàng triệu gói tin biến thể, dựa vào phản hồi của server để giải mã Pre-Master Secret, từ đó giải mã toàn bộ phiên TLS.
    * **Khắc phục:** Loại bỏ hoàn toàn RSA Key Exchange trong cấu hình TLS server (chuyển sang dùng (EC)DHE cho Key Exchange và chỉ dùng RSA để ký). Nâng cấp lên TLS 1.3 (đã loại bỏ PKCS#1 v1.5 padding cho mã hóa).

### Bảng tổng hợp giải pháp triển khai:
| Triển khai | Weakness | Giải pháp |
|---|---|---|
**1. TLS (Web Server)** | **a. Không forward secrecy (TLS 1.2):** Nếu Attacker lấy được $d$, sẽ giải mã được toàn bộ các phiên quá khứ do Server dùng chung tham số $(n, e, d)$ cho mã hóa.<br><br>**b. Kịch bản Bleichenbacher Attack (TLS 1.2):** Attacker ép Server chọn RSA Cipher Suite, dùng Server làm Oracle để lấy PreMasterSecret. | - **Sử dụng TLS 1.3:** Đã loại bỏ hoàn toàn trao đổi khóa RSA, chỉ sử dụng ECDHE (đảm bảo tính forward secrecy).<br>- Trong TLS 1.3, Server ký toàn bộ transcript, Attacker không thể thay đổi quá trình bắt tay. |
| **2. JWT / token signing (RS256) (G-check)** | **Weak signing tools / key exposure:** Private key (file `.pem`/biến môi trường) lưu trên code repo hoặc build server. Attacker copy được sẽ tự ký "Golden Token" (leo quyền Admin). | - Không lưu private key trên đĩa cứng server ứng dụng.<br>- Sử dụng **HSM** hoặc dịch vụ **quản lý khóa đám mây** (AWS KMS, Azure Key Vault).<br>- Private key không bao giờ rời khỏi thiết bị bảo mật. |
| **3. Code signing & package ecosystems** |**Weak signing tools / key exposure:** Private key (file `.pem`/biến môi trường) lưu trên code repo hoặc build server. Attacker copy được sẽ tự ký "Golden Token" (leo quyền Admin).<br> **Legacy signature format:** là các lược đồ hoặc định dạng chữ ký lỗi thời cho phép một message có thể có nhiều chữ ký hợp lệ khác nhau, dù được ký bằng cùng một private key. Dẫn đến: <br>- **Signature Malleability:** Có nhiều chữ ký được verify hợp lệ cho cùng một message → Message không thay đổi, chữ ký thay đổi nhưng vẫn hợp lệ.<br>- **Replay Attack:** Signature Malleability + Sử dụng Signature làm ID định danh action.   |- Không lưu private key trên đĩa cứng server ứng dụng.<br>- Sử dụng **HSM** hoặc dịch vụ **quản lý khóa đám mây** (AWS KMS, Azure Key Vault).<br>- Private key không bao giờ rời khỏi thiết bị bảo mật. <br> - Không sử dụng Signature làm ID định danh hành động(sử dụng Nonce thay thế), tách biệt vai trò của Signature và ID <br>- Hệ thống cần chỉ chấp nhận chữ ký ở dạng canonical, và từ chối các chữ ký có biểu diễn khác nhưng vẫn verify được.|
| **4. Smartcards / HSMs / TPMs** | **a. Side-channel (Power Analysis):** Đo dao động điện năng để tái tạo private key.<br>**b. Fault Injection (RSA-CRT):** Dùng laser/điện áp gây lỗi tính toán $\to$ lộ thừa số nguyên tố ($p$ hoặc $q$).<br>**c. API misuse:** Dùng HSM làm Oracle giải mã hoặc dùng sai quyền hạn key. | - Dùng smartcard chuẩn **FIPS 140-2 Level 3+** (có mesh shield).<br>- **Verify on-chip:** Kiểm tra chữ ký trên chip trước khi xuất, nếu sai thì hủy phiên.<br>- **Key Wrapping:** Chỉ wrap key, không decrypt dữ liệu thô.<br>- Giới hạn **Usage Flags**: Chỉ `Sign` hoặc `Decrypt`, không bật cả hai. |
| **5. Random Number Generator (RNG)** | **RNG kém:** Không dùng TRNG hoặc dùng PRNG tự chế $\to$ sinh số không đủ ngẫu nhiên $\to$ trùng thừa số $p$ $\to$ tính được private key bằng GCD. | - Sử dụng **TRNG** để sinh entropy (seed).<br>- Sử dụng PRNG theo chuẩn **NIST** (Hash_DRBG, HMAC_DRBG, AES-CTR-DRBG, ChaCha20-DRBG).<br>- Sử dụng HSM/TPM khi có thể. |
| **6. Implementation bugs & side channels** | **a. Timing leaks:** Chênh lệch thời gian tính toán (Square-and-Multiply) làm lộ $d$.<br>**b. CRT recombination faults (Bellcore Attack):** Lỗi khi tính $S_p$ dẫn đến lộ $q$.<br>**c. Padding oracle (Bleichenbacher/ROBOT):** Server phản hồi lỗi khác nhau với định dạng `00 02` sai $\to$ Attacker giải mã được Pre-Master Secret. | - Cài đặt **Constant-time** (thời gian không phụ thuộc dữ liệu).<br>- Dùng kỹ thuật **Blinding**.<br>- Luôn kiểm tra lại kết quả $S^e \equiv M \pmod N$ trước khi trả về $S$.<br>- Loại bỏ RSA Key Exchange (chuyển sang (EC)DHE).<br>- Nâng cấp lên **TLS 1.3**. |

---

## V. Conclusion

Trong đồ án này, chúng tôi đã tiến hành khảo sát và phân tích toàn diện thuật toán RSA và các cơ chế chữ ký số dựa trên RSA, không chỉ ở khía cạnh lý thuyết toán học mà quan trọng hơn là ở các điểm yếu phát sinh trong quá trình triển khai và sử dụng thực tế. Thông qua việc nghiên cứu nhiều lớp tấn công khác nhau như factoring attack, padding oracle attack, key generation weakness, cũng như các tấn công ở mức triển khai (side-channel, fault attack), đồ án cho thấy rằng tính an toàn của RSA không chỉ phụ thuộc vào độ khó của bài toán phân tích thừa số, mà phụ thuộc rất lớn vào cách hệ thống thiết kế, cài đặt và vận hành RSA trong môi trường thực tế.

Các tấn công như Bleichenbacher, Marvin, hay RSA-CRT fault attack minh họa rõ ràng rằng RSA thường **không bị phá vỡ trực tiếp về mặt toán học**, mà bị khai thác thông qua rò rỉ thông tin phụ như lỗi padding, sai khác thời gian xử lý, hoặc lỗi phần cứng. Điều này nhấn mạnh rằng việc lựa chọn kích thước khóa lớn là **chưa đủ** nếu không đi kèm với padding an toàn, xử lý constant-time, nguồn sinh số ngẫu nhiên chất lượng cao và các biện pháp bảo vệ ở tầng triển khai.

Bên cạnh đó, phân tích các kịch bản triển khai hiện đại như TLS, JWT/RS256, code signing và HSM cho thấy nhiều cơ chế cũ (đặc biệt là PKCS#1 v1.5 và RSA key exchange trong TLS 1.2) tiềm ẩn rủi ro nghiêm trọng và cần được **loại bỏ hoặc thay thế một cách có chủ đích**. Việc chuyển sang các chuẩn hiện đại như RSA-OAEP, RSA-PSS, (EC)DHE và TLS 1.3 là yêu cầu tất yếu để đảm bảo an toàn dài hạn.

Tóm lại, RSA vẫn có thể được sử dụng an toàn **chỉ khi** đi kèm với các chuẩn thiết kế hiện đại và triển khai cẩn trọng. Chúng tôi có thể khẳng định một nguyên lý cốt lõi trong mật mã học ứng dụng: **phần lớn các sự cố an ninh không xuất phát từ việc thuật toán bị phá, mà từ cách thuật toán được triển khai và sử dụng trong thực tế**. Việc hiểu rõ các điểm yếu này là nền tảng quan trọng để xây dựng, đánh giá và vận hành các hệ thống mật mã an toàn.

## VI. Reference 
[1]. https://en.wikipedia.org/wiki/RSA_cryptosystem
[2]. [Dan Boneh. Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)
[3]. [Daniel Bleichenbacher. Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1](https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)
[4]. [Everlasting ROBOT: the Marvin Attack](https://people.redhat.com/~hkario/marvin/marvin-attack-paper.pdf)
[5]. [Fault attacks for CRT based RSA: new attacks, new results, and new countermeasures](https://dl.ifip.org/db/conf/wistp/wistp2007/KimQ07.pdf)
[6]. [Kocher. Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems ](https://paulkocher.com/doc/TimingAttacks.pdf)
[7]. https://en.wikipedia.org/wiki/Digital_signature








