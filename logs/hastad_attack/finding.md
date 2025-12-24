# Finding 
Nhận xét rằng dù cho `e` thế nào, nếu ta có đủ `k>=e` cặp `n` và ciphertext tương ứng với `n` thì **Hastad Attack** luôn thành công. Nhưng tất nhiên rằng khi `e` nhỏ thì khả năng có đủ `k>=e` cặp dữ liệu như thế sẽ lớn hơn. 

Bên cạnh đó cũng cần lưu ý rằng điều kiện trên (đủ `k>=e` cặp `n` và ciphertext tương ứng với `n`) chỉ là điều kiện đủ, có thể không thỏa điều kiện này thì **Hastad Attack** vẫn diễn ra thành công, điều kiện quan trọng nhất vẫn là tìm được `N` thỏa: `m^e < N`

Ngoài ra, ta cũng quan sát được thời gian tấn công tăng lên khá nhanh khi `e` tăng, vì khi đó số phương trình lớn, giải thuật CRT cần nhiều thời gian để giải hệ phương trình đó. Nhưng nhìn chung, ta chỉ xét tấn công này khi `e` nhỏ và khi `e`  nhỏ thì thời gian thực hiện tấn công như vậy là rất nhanh(`e = 61` thì khôi phục được plaintext trong xấp xỉ 130s)