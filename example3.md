# Delphi import unit per OpenSSL DLL

## Generate a RSA keypair
## _Generare una coppia di chiavi RSA_

_Richiede [OpenSSLUtils.pas](OpenSSLUtils.pas)_

Require [OpenSSLUtils.pas](OpenSSLUtils.pas)

```
procedure GenerateKeyPair;
var
  kp: TKeyPairGenerator;
begin
kp := TKeyPairGenerator.Create;
kp.KeyFileNames('c:\temp\mykeys');  // it create a pair c:\temp\mykeys.key
                                    // and c:\temp\mykeys.pub
kp.Password := 'mypasswd';          // Required
kp.GenerateRSA;
end;
```

_Ecco il frammento di OpenSSLUtils.pas_

This is the OpenSSLUtils.pas snippet

```
procedure TKeyPairGenerator.GenerateRSA;
var
  rsa: pRSA;
  PrivateKeyOut, PublicKeyOut, ErrMsg: pBIO;
  buff: array [0..1023] of char;
  enc: pEVP_CIPHER;
begin
if (fPrivateKeyFile = '') or (fPublicKeyFile = '') then
  raise EOpenSSL.Create('Key filenames must be specified.');
if (fPassword = '') then
  raise EOpenSSL.Create('A password must be specified.');

ERR_load_crypto_strings;
OpenSSL_add_all_ciphers;

enc := EVP_des_ede3_cbc;

// Load a pseudo random file
RAND_load_file(PChar(fSeedFile), -1);

rsa := RSA_generate_key(fKeyLength, RSA_F4, nil, ErrMsg);
if rsa=nil then
  begin
  BIO_reset(ErrMsg);
  BIO_read(ErrMsg, @buff, 1024);
  raise EOpenSSL.Create(PChar(@buff));
  end;

PrivateKeyOut := BIO_new(BIO_s_file());
BIO_write_filename(PrivateKeyOut, PChar(fPrivateKeyFile));
PublicKeyOut := BIO_new(BIO_s_file());
BIO_write_filename(PublicKeyOut, PChar(fPublicKeyFile));

PEM_write_bio_RSAPrivateKey(PrivateKeyOut, rsa, enc, nil, 0, nil, PChar(fPassword));
PEM_write_bio_RSAPublicKey(PublicKeyOut, rsa);

if rsa <> nil then RSA_free(rsa);
if PrivateKeyOut <> nil then BIO_free_all(PrivateKeyOut);
if PublicKeyOut <> nil then BIO_free_all(PublicKeyOut);
end;
```
