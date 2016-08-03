#Nodejs Cryptogram Example

nodejs cryptogram wrapper API

- des
- aes
- seed
- mac
- hash
- RSA
- padding


## Example

### DES ECB 

```
// DES ECB
var des = require('node-cardcrypto').des;

//hex string or Buffer
var deskey1 = '7CA110454A1A6E57';
var plain = '01A1D6D039776742';

var answer = '690F5B0D9A26939B';

var result = des.ecb_encrypt(deskey1, plain);
assert(answer === result);
```

```
// Triple DES ECB
var plain = '01A1D6D039776742';

var deskey1 = '7CA110454A1A6E57';
var deskey2 = '0131D9619DC1376E';

var deskey = deskey1 + deskey2;

cipher = plain;
cipher = des.ecb_encrypt(deskey1, cipher);
cipher = des.ecb_decrypt(deskey2, cipher);
cipher = des.ecb_encrypt(deskey1, cipher);

result = des.ecb_encrypt(deskey, plain);
assert(result === cipher);
```


## Installation
You can install the latest tag via npm:

	npm install node-cardcrypto