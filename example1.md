# Delphi import unit per OpenSSL DLL

## How to get OpenSSL DDL version
## _Leggere la versione della DLL di OpenSSL_

```
function GetVersion: string;
var
  v: cardinal;
  s: PChar;
begin
v := SSLeay;
s := SSLeay_version(_SSLEAY_CFLAGS);
result := s + ' (' + IntToHex(v, 9) + ')';
end;
```

Result is described in OPENSSL_VERSION_NUMBER(3) man page

_Il risultato &egrave; descritto nel pagina man OPENSSL_VERSION_NUMBER(3)_