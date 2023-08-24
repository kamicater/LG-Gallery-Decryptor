# LG Gallery Decryptor
Decrypt your encrypted images (\*.jpg.dm) and videos (\*.mp4.dm) from the LG Gallery App. You need to know your gmail address. It's also possible to decrypt your multimedia files if you don't remember your gmail address.

Based on the paper **"A study on LG content lock and data aquisition from apps based on content lock function"** from Giyoon Kim, Myungseo Park and Jongsung Kim from 28 September 2021.

Please use at your own advice. There is no error handling.

## How to use:

Create two folders ```encrypted``` and ```decrypted``` in the same directory.

Create a file to run the decryption with multiple files:

```bash
#!/bin/bash
python lgdecryptor.py 20161230_133055.jpg.dm
python lgdecryptor.py 20161230_134050.mp4.dm
...
```
