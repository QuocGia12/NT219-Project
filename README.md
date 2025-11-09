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

## Project Goals
- Present in detail the theory of RSA and RSA digital signatures: how they work, the mathematical foundations, the RSA-CRT performance optimization, and the core issues of RSA.
- Present several classical attack models against RSA encryption and digital signatures: the mathematical basis behind them, and safe PoC (proof-of-concept) implementations of the attacks
  - Håstad’s attack on low public exponents and common-modulus scenarios.
  - Wiener’s attack: small private exponent attack.
  - Fault attacks on RSA-CRT.
  - Bleichenbacher’s padding oracle attack on PKCS#1 v1.5.
- Assess the risks in deployment scenarios (TLS/HTTPS, smartcards/HSMs) 
- This project concentrates on **cryptanalytic attacks against the mathematical foundations of RSA**, as opposed to attacks exploiting protocol or implementation vulnerabilities.. 
- Propose mitigation and remediation measures.

## I. Asset‑Centric Context (AIM)
### 1. Asset
The primary assets that this project aims to protect or assess the risks of include:

* **Private RSA keys** (e.g., server TLS keys, code-signing keys, JWT signing keys).
* **Signed artifacts and tokens** (e.g., TLS sessions, JWT/ID tokens, code-signing signatures).
* **Session secrets** (e.g., the *PreMasterSecret* in TLS ≤1.2 when RSA key exchange is used).
* **HSM/smartcard-stored keys** (key material residing inside hardware security modules).
* **Device key-generation entropy** (RNG/seed quality affecting the randomness of generated primes *p* and *q*).
### 2. Stakeholders and Roles
- **Key Owner**: Generates, stores, and uses the RSA key pair.  
- **Certificate Authority (CA)**: Verifies identities and issues digital certificates.  
- **Registration Authority (RA)**: Acts as an intermediary that validates the identity of entities before certificate issuance.  
- **Security Administrator / PKI Operator**: Manages the key and certificate infrastructure, including lifecycle, revocation, and policy enforcement.

## II. Basic Theory of RSA and RSA-Based Signatures

### Basic Theory of RSA
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

### RSA-Based Digital Signatures
In addition to encryption, RSA is also applied to digital signatures. The idea works similarly to encryption, but now the order of using the private key and public key is reversed.  

Suppose Alice wants to send Bob a document along with her signature. In this case, Alice keeps a private key $(N, d)$, while Bob holds the corresponding public key $(N, e)$.  

- Alice computes the hash value of the entire document she wants to send, denoted as $hash$.  
- The digital signature of the document Alice wants to send is calculated as: $sig \equiv hash^{d} \mod{N}$.  
- Alice sends the document together with the computed digital signature.  
- When Bob receives it, he computes $hash \equiv sig^{e} \mod{N}$, then calculates the hash value of the received document. If this value matches $hash$, it proves that the sender knows Alice’s private key and that the document has not been altered during transmission.
### RSA Optimizations  
#### Time Complexity Drawbacks of RSA  
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

#### RSA-CRT  
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

### The Core Problem in RSA
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

## III. Theoretical of the Attack
### 1. Bleichenbacher (1998) on PKCS#1 v1.5 padding oracle attack.
#### Tổng quan ngắn
Bleichenbacher (1998) là cuộc tấn công **padding-oracle** nổi tiếng nhắm vào chuẩn **PKCS#1 v1.5** cho RSA (dùng trong nhiều giao thức cũ như SSL/TLS). 
Ý tưởng chính: nếu bạn có **oracle** trả lời cho bạn biết “sau khi giải được (RSA-decrypt), padding có hợp lệ theo PKCS#1 v1.5 hay không” (yes/no), thì bằng cách gửi nhiều ciphertext tùy chỉnh bạn có **lần lượt rút hẹp khoảng giá trị** của plaintext gốc và cuối cùng phục hồi toàn bộ thông điệp — tất cả mà không cần biết khóa riêng.

#### PKCS#1 v1.5 padding 

Khi RSA dùng cho mã hóa theo PKCS#1 v1.5, plaintext (M) trước khi mã hóa có dạng:

```
EM = 0x00 || 0x02 || PS || 0x00 || D
```

* 0x02 chỉ ra chế độ mã hóa (khác với 0x01 cho signatures),
* PS(padding string) là một chuỗi padding ngẫu nhiên (ít nhất 8 byte, không chứa byte 0x00),
* `D` là dữ liệu/khóa (message) thực sự.

Một plaintext/ciphertext được gọi là **PKCS conforming** khi nó thỏa đủ 3 yêu cầu sau: 
- 2 byte đầu tiên của plaintext tương ứng lần lượt là `0x00` và `0x02`
- Byte thứ 3 đến byte 10 không được là byte `0x00` 
- Tồn tại ít nhất một byte nằm sau byte thứ 10 là byte `0x00`

#### Một số tính chất toán học dùng trong tấn công
Gọi $k$ là số bytes biểu diễn của $n$
Đầu tiên ta sẽ nói về một số tính chất toán học sẽ được dùng trong tấn công này: 
##### Tính chất 1
> Với $s$ bất kì thì: Nếu $c=m^e\mod n$ thì plaintext tương ứng với ciphertext $c'=c\cdot s^e\mod n$ là $m'=m \cdot s \mod n$
> 
Thật vậy: 
$$
(c')^d\equiv (c\cdot s^e)^d\equiv c^d \cdot s^{ed}=m \cdot s \mod n 
$$
##### Tính chất 2
> Nếu plaintext m thỏa PKCS conforming thì: 
$$
2B\leq m \mod n\leq3B-1 \text{ với } B=2^{8(k-2)}
$$

Chú ý: việc đặt $B=2^{8(k-2)}$ sẽ được sử dụng xuyên suốt trong phần này 

#### Ý tưởng tấn công 
Ý tưởng của Bleichenbacher on PKCS#1 v1.5 padding oracle attack như sau: 
Lần lượt tìm $s$ thỏa $c \cdot s^e$ là một ciphertext PKCS conforming 
→ $2B\leq ms \mod n\leq3B-1$
→ Tồn tại số nguyên $r$ thỏa: $2B\leq ms-rn\leq3B-1$
→ $\frac{2B+rn}{s} \leq m \leq \frac{3B-1+rn}{s}$

Suy ra, ta giới hạn lại $m$ chỉ còn thuộc một khoảng nhất định.

Ứng với mỗi $s$ tìm được, ta sẽ tiếp tục giới hạn lại khoảng có thể có của $m$(kết hợp với các khoảng ta đã tìm được trước đó) cho đến khi khoảng có thể có của $m$ chỉ còn là $[a, a]$, khi đó ta tìm được $m=a$

Tuy nhiên, để **tối ưu số lần query gửi đến oracle**, ta cần một cách chọn $s$ hiệu quả để khả năng bắt gặp $s$ thỏa $c \cdot s^e$ là một ciphertext PKCS conforming là cao nhất.
#### Thuật toán tấn công 
Gọi $c_0$ là ciphertext mà ta cần tấn công, $m_0$ là plaintext mà ta cần tìm
Gọi $M_i$ là biến lưu tập hợp của những khoảng có thể chứa $m_0$ sau khi tìm được $s_i$ thỏa mãn 
##### Bước 1: Tìm $s_i$ thỏa mãn $c_0(s_i)^e$ là một ciphertext thỏa PKCS conforming 
Để tối ưu số lần query gửi đến oracle, tấn công này chia thành 3 trường hợp, mỗi trường hợp có một chiến thuật tìm $s_i$ khác nhau 
###### a. Nếu $i=1$
> Tìm số nguyên nhỏ nhất $s_1\geq \frac{n}{3B}$ thỏa ciphertext $c_0(s_1)^e$ là PKCS conforming 

Giải thích lí do: 
Nếu $s_1< \frac{n}{3B}$ 
→ $m_0\cdot s_1<3B \cdot \frac{n}{3B}=n$(chú ý $m_0$ là plaintext PKCS conforming nên $2B\leq m_0<3B$)
→ Khi đó: việc $\mod n$ không có tác dụng 
→ $2B\leq m_0\cdot s_1<3B$ **(*)** 
Tuy nhiên điều này là không thể vì với $s_1>=2$ và $2B\leq m_0<3B$ dẫn đến $m_0\cdot s_1\geq4B>3B$, ngược với lại **(*)**

Suy ra, nếu $s_1< \frac{n}{3B}$ thì $c_0(s_1)^e$ không thể là ciphertext PKCS conforming, vì thế $\frac{n}{3B}$ là mốc đầu tiên ta dùng để bắt đầu tìm $s_1$
###### b. Nếu $i>1$ và $M_i$ chứa nhiều hơn 1 khoảng 
> Tìm $s_i$ nhỏ nhất $>s_{i-1}$ thỏa ciphertext $c_0\cdot s_i^e$ là PKCS conforming 

Ta lần lượt tìm $s_i$ tăng dần để tránh chọn lại những $s$ thỏa mãn ta đã chọn trước đó 
###### c. Nếu $i>1$ và $M_i$ chỉ chứa một khoảng $[a, b]$
Lúc này, khi biết $m_0$ chỉ có thể nằm trong khoảng $[a, b]$, ta có chiến thuật chọn $s_i$ khác để khả năng ciphertext $c_0 \cdot s^e$ thỏa PKCS conforming là cao 

Ta cần tìm $s_i$ và $r_i$ thỏa mãn $2B\leq m_0s_i-r_in\leq3B-1$, chú ý bây giờ ta đã biết được $a\leq m_0\leq b$
Cố định $r_i$, từ hai bất đẳng thức trên ta suy ra được $\frac{2B+r_in}{b}\leq s_i\leq \frac{3B+r_in}{a}$ (thường thì khoảng này khá nhỏ)

Để $s_i\geq s_{i-1}+1$ thì điều kiện đủ là $s_{min}(r)\geq s_{i-1}+1$
Suy ra: $\frac{2B+r_in}{b}\geq s_{i-1}+1$
→ Biến đổi bất đẳng thức trên, ta được $r_i\geq\frac{b(s_{i-1}+1)-2B}{n}$

> Tìm $s_i$ và $r_i$ thỏa mãn: 
> - $r_i\geq\frac{b(s_{i-1}+1)-2B}{n}$
> - $\frac{2B+r_in}{b}\leq s_i\leq \frac{3B+r_in}{a}$ (thường thì khoảng này khá nhỏ)
##### Bước 2: Thu hẹp $M_i$

> Sau khi $s_i$ được tìm thấy, tập $M_i$ được tính như sau
$$
M_i \leftarrow \bigcup_{(a,b,r)} \left\{ \left[\; \max\!\Big(a,\; \left\lceil\frac{2B + r n}{s_i}\right\rceil\Big),\; \min\!\Big(b,\; \left\lfloor\frac{3B - 1 + r n}{s_i}\right\rfloor\Big)\right]\; \right\}
$$
với mọi $([a,b]\in M_{i-1})$ và mọi $r$ thỏa
$$
\left\lceil\frac{a s_i - 3B + 1}{n}\right\rceil \le r \le \left\lfloor\frac{b s_i - 2B}{n}\right\rfloor.
$$

**Giải thích ngắn:**  
Với mỗi khoảng $[a,b]$ trong $M_{i-1}$ và mỗi giá trị nguyên $r$ trong đoạn trên, ta xét khoảng nguyên

$$
\left[\left\lceil\frac{2B + r n}{s_i}\right\rceil,\; \left\lfloor\frac{3B - 1 + r n}{s_i}\right\rfloor\right]
$$

và lấy giao của nó với $[a,b]$. Tập hợp tất cả các giao không rỗng thu được chính là $M_i$.

##### Bước 3: Tính kết quả 
- Nếu $M_i$ chỉ còn chứa một khoảng $[a, a]$ thì $m_0$ cần tìm chính là $a$
- Ngược lại, quay về bước 1 

#### Áp dụng Bleichenbacher's Attack trong chữ kí số 
Bây giờ ta nói về việc phân tích áp dụng **Bleichenbacher's Attack** vào việc chữ kí số RSA như sau: 
> Attacker cần kí một message có hash là $h$. 
> Tức vấn đề bây giờ đặt ra là: liệu attacker có thể tìm được $h^d$ nếu attacker có một oracle cho phép nhận biết một ciphertext có là PKCS conforming hay không. 

Câu trả lời là có 
Để tìm $h^d$, attacker thực hiện như sau: 
- Tìm $s_0$ thỏa $hs_0^e$ là một ciphertext PKCS conforming 
- Đặt $c_0=hs_0^e \mod n$
- Thực hiện Bleichenbacher's Attack như trên → attacker tìm được $c_0^d=(hs_0^e)^d=h^d\cdot s_0^{ed}=h^d \cdot s_0 \mod n$
- Attacker tính $h^d=c_0^d\cdot s_0^{-1} \mod n$ với $s_0^{-1} \mod n$
 là nghịch đảo module $n$ của $s_0$

#### Biện pháp phòng ngừa (ngay lập tức và khuyến nghị)

1. **Ngừng dùng PKCS#1 v1.5 cho mã hóa**; dùng **RSA-OAEP** cho mã hóa dữ liệu (OAEP là thiết kế chống chosen-ciphertext).
2. **Không tiết lộ trạng thái padding trong lỗi**: thống nhất lỗi chung chung cho mọi trường hợp thất bại (ví dụ đều trả "decryption failed" mà không phân biệt).
3. **Thực hiện kiểm tra padding constant-time**: tránh rò rỉ qua timing.
4. **Sử dụng RSA blinding** để giảm side-channel timing (nhưng blinding không ngăn oracle trả true/false về padding — chỉ chống timing side-channels).
5. **Sử dụng authenticated key exchange / AEAD** (ví dụ sử dụng Diffie-Hellman + AEAD) thay vì trực tiếp RSA-encrypting pre-master.
6. **Giảm tối đa số truy vấn có thể gửi tới oracle**: rate-limit, giám sát traffic bất thường.
7. **Cập nhật thư viện / patch**: các thư viện lớn (OpenSSL, NSS, Microsoft SChannel, v.v.) đã vá nhiều trường hợp; luôn chạy phiên bản được vá.




### 2. Wiener (1990) on small private exponent attack.

#### Nhắc lại công thức RSA

RSA có: 
* $( n = p \cdot q )$
* $( \varphi(n) = (p-1)(q-1) )$
* $( e \cdot d \equiv 1 \pmod{\varphi(n)} )$

Nghĩa là: $e \cdot d = 1 + k\varphi(n)$,  với $k$ là số nguyên dương.

#### Khi d quá nhỏ

Nếu d nhỏ, tức là: $d < n^{0.25} / 3$ thì **Wiener (1990)** chứng minh rằng có thể **tính lại d** từ **(e, n)** bằng **phân số liên tục (continued fractions)**.

Ý tưởng là:

* Do $( e \cdot d - k\varphi(n) = 1 )$, nên:
$$
  \frac{e}{n} \approx \frac{k}{d}
$$
* Từ đó, kẻ tấn công có thể dùng **phân số liên tục (continued fraction)** để tìm xấp xỉ của $e/n$, thử các cặp $(k_i, d_i)$ để tìm ra $d$ thật sự.

#### Hậu quả

Nếu tìm được $d$, thì:

* Kẻ tấn công **giải mã được mọi ciphertext**: $m = c^d \bmod n$
* Hoặc **ký giả mạo** các thông điệp RSA-signature hợp lệ.


#### Nguyên nhân thực tế có thể dẫn đến “d nhỏ”

* Hệ thống cố ý chọn $d$ nhỏ để **tăng tốc giải mã** (vì giải mã = $c^d \mod n$ ).
* Hoặc chọn $e$ quá lớn → khiến $d$ nhỏ do $e \cdot d ≡ 1 \pmod{\varphi(n)}$.


#### Biện pháp phòng tránh

* Không bao giờ chọn $d < n^{0.25}$.
* Thực tế, hầu hết các hệ thống dùng:

  * $e = 65537$
  * $d$ ngẫu nhiên đủ lớn (vì được sinh tự động từ hàm inverse mod).
* Hoặc dùng **RSA-CRT**, **RSASSA-PSS** để cải thiện tốc độ mà vẫn an toàn.


Nếu $d$ thực sự nhỏ (thỏa điều kiện Wiener), thì có thể **phục hồi được d trong vài giây**.

---

**Tóm lại:**

> Khi $d$ nhỏ, RSA không còn an toàn — có thể bị tấn công bằng Wiener’s Attack vì mối quan hệ tuyến tính giữa $e/n$ và $k/d$.

### 3. Håstad’s attack on low exponents and common modulus scenarios

#### Bối cảnh

RSA mã hóa một thông điệp $m$ thành:

$$
c = m^e \mod n
$$

với $e$ là **public exponent** (thường nhỏ, như 3 hoặc 5)
và $n = pq$ là modulus.

Håstad’s Broadcast Attack tấn công vào điểm yếu sau: 
> Nếu e đủ nhỏ làm cho $m^e<n$ thì khi đó việc $\mod n$ trong $c=m^e \mod n$ không còn tác dụng, suy ra $m = \sqrt[e]{c}$

#### Håstad’s Broadcast Attack (1985)

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

#### Common Modulus Attack

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

#### Biện pháp phòng tránh

* **Không dùng RSA raw** (luôn thêm padding ngẫu nhiên như **OAEP**), khi đó $m$ được tăng lên gần với $n$, hạn chế hoàn toàn khả năng $m^e<n$
* Không dùng chung modulus giữa nhiều người.
* Dùng **exponent đủ lớn**.
