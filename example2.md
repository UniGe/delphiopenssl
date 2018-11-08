# Delphi import unit per OpenSSL DLL

## How to compute SHA1 digest
## _Calcolare il digest SHA1 di una stringa_

```
function SHA1(msg: string): string;
var
  mdLength, b64Length: integer;
  mdValue: array [0..EVP_MAX_MD_SIZE] of byte;
  mdctx: EVP_MD_CTX;
  memout, b64: pBIO;
  inbuf, outbuf: array [0..1023] of char;
begin
StrPCopy(inbuf, msg);
EVP_DigestInit(@mdctx, EVP_sha1());
EVP_DigestUpdate(@mdctx, @inbuf, StrLen(inbuf));
EVP_DigestFinal(@mdctx, @mdValue, mdLength);
mdLength := EVP_MD_CTX_size(@mdctx);
b64 := BIO_new(BIO_f_base64);
memout := BIO_new(BIO_s_mem);
b64 := BIO_push(b64, memout);
BIO_write(b64, @mdValue, mdLength);
BIO_flush(b64);
b64Length := BIO_read(memout, @outbuf, 1024);
outbuf[b64Length-1] := #0;
result := StrPas(@outbuf);
end;
```