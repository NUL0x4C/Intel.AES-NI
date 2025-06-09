### Intel.AES-NI: Leveraging Intel AES-NI for AES-128 & AES-256 Encryption Modes

</br>

**This repository implements the following AES modes (both 128- and 256-bit keys), all accelerated with Intel AES-NI intrinsics:**

| Mode    | Security | Performance | AEAD / Auth | Padding Req'd? |
| :------ | :------: | :---------: | :---------: | :------------: |
| **ECB** |    1/5   |     5/5     |      No     |       Yes      |
| **CBC** |    3/5   |     3/5     |      No     |       Yes      |
| **CFB** |    3/5   |     3/5     |      No     |       No       |
| **CTR** |    3/5   |     5/5     |      No     |       No       |
| **GCM** |    4/5   |     5/5     |     Yes     |       No       |
| **OCB** |    5/5   |     5/5     |     Yes     |       No       |
| **XTS** (#) |    4/5   |     4/5     |     No (*)    |       No       |
| **OFB** (#) |    2/5   |     4/5     |      No     |       No       |
| **EAX** |    5/5   |     4/5     |     Yes     |       No       |
| **LRW** (#) |    4/5   |     4/5     |      No     |       No       |


* **(*) XTS provides confidentiality with a tweak (no built-in authentication).**
* **(#) Not implemented yet**

</br>
