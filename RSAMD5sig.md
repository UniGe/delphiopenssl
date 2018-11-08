# Delphi import unit per OpenSSL DLL

## RSA+MD5 signature

A nice contribute by Dim (Russia)

Require [libeay32.pas](libeay32.pas), v. >= 0.7

```
// Equivalent to:
//   <b>openssl dgst -md5 -sign private.pem -hex -out test.hex <test.txt</b>
function Sign_RSA_MD5(privatekey,msg: string): string;
var
Len: cardinal;
mdctx: EVP_MD_CTX;
inbuf, outbuf: array [0..1023] of char;
key: pEVP_PKEY;
begin
StrPCopy(inbuf, msg);
InitOpenSSL;
key:=ReadPrivateKey(privatekey);
EVP_SignInit(@mdctx, EVP_md5());
EVP_SignUpdate(@mdctx, @inbuf, StrLen(inbuf));
EVP_SignFinal(@mdctx, @outbuf, Len, key);
FreeOpenSSL;
BinToHex(outbuf, inbuf,Len);
inbuf[2*Len]:=#0;
result := StrPas(inbuf);
end;
```