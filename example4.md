# Delphi import unit per OpenSSL DLL

## S/MIME message signing
## _Firma S/MIME di un messaggio_

_Richiede [OpenSSLUtils.pas](OpenSSLUtils.pas)_

Require [OpenSSLUtils.pas](OpenSSLUtils.pas)

```
procedure Sign: string;
var
  signer: TMessageSigner;
begin
signer := TMessageSigner.Create;
signer.LoadPrivateKey('h:\user.key', 'userpw');
signer.LoadCertificate('h:\user.crt');
signer.PlainMessage := 'Hello world.';
signer.MIMESign;
result := signer.SignedMessage;
end;
```

_Ecco il frammento di OpenSSLUtils.pas_

This is the OpenSSLUtils.pas snippet

```
procedure TMessageSigner.MIMESign;
var
  p7: pPKCS7;
  msgin, msgout: pBIO;
  buff: PChar;
  buffsize: integer;
begin

// Load private key if filename is defined
if fKey = nil then
  begin
  if fPrivateKeyFile <> '' then
    LoadPrivateKey(fPrivateKeyFile, fPassword)
  else
    raise EOpenSSL.Create('Private key is required.');
  end;

// load signer certificate
if fCertificate = nil then
  begin
  if fPrivateKeyFile <> '' then
    LoadCertificate(fCertificateFile)
  else
    raise EOpenSSL.Create('Signer certificate is required.');
  end;

msgin := BIO_new_mem_buf(PChar(fMessage), -1);
msgout := BIO_new(BIO_s_mem);
p7 := PKCS7_sign(fCertificate, fKey, fOtherCertificates, msgin, PKCS7_DETACHED);
BIO_reset(msgin);
SMIME_write_PKCS7(msgout, p7, msgin, PKCS7_TEXT or PKCS7_DETACHED);
// Count used byte
buffsize := BIO_pending(msgout);
GetMem(buff, buffsize+1);
BIO_read(msgout, buff, buffsize);
fSignedMessage := StrPas(buff);
FreeMem(buff);
end;
```

