# LG Gallery Decryptor
Decrypt your encrypted images (\*.jpg.dm) and videos (\*.mp4.dm) from the LG Gallery App. You need to know your gmail address. It's also possible to decrypt your multimedia files if you don't remember your gmail address.

Based on the paper **"A study on LG content lock and data aquisition from apps based on content lock function"** from Giyoon Kim, Myungseo Park and Jongsung Kim from 28 September 2021.

Please use at your own advice. There is no error handling.

## Installation
Install the needed dependencies:
```bash
python3 -m pip install -r requirements.txt
```

## How to use:
You can use the help to see an explanation of all of the arguments:
```bash
python3 lgdecryptor.py --help
```

Example decrypting a single file:
```bash
python3 lgdecryptor.py youremail@gmail.com 20161230_133055.jpg.dm
```

Example decrypting multiple files:
```bash
python3 lgdecryptor.py youremail@gmail.com 20161230_133055.jpg.dm 20161230_134050.mp4.dm
```

Example decrypting multiple files using globbing:
```bash
python3 lgdecryptor.py youremail@gmail.com *.dm
```

The output directory can be changed as so:
```bash
python3 lgdecryptor.py -o decrypted/ youremail@gmail.com *.dm
```
