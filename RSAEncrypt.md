# Delphi import unit per OpenSSL DLL

## File encryption using a RSA private key

Require [libeay32.pas](libeay32.pas), v. >= 0.7

```
// Equivalent to:
//   <b>openssl rsautl -encrypt -in CleartextFile -out CryptedFile -inkey KeyFile</b>
// Probably you should set padding := RSA_PKCS1_PADDING
procedure TMainForm.RSAEncrypt(KeyFile, CleartextFile, CryptedFile: string; padding: integer);
var
  rsa: pRSA;
  keysize: integer;

  key: pEVP_PKEY;
  cleartext, crypted: pBIO;
  rsa_in, rsa_out: pointer;
  rsa_inlen, rsa_outlen: integer;
begin
// as in AskPassphrase.md
key := ReadPrivateKey(KeyFile);
rsa := EVP_PKEY_get1_RSA(key);
EVP_PKEY_free(key);
if rsa = nil then
  raise Exception.Create('Error getting RSA key. ' + GetErrorMessage);

cleartext := BIO_new_file(PChar(CleartextFile), 'rb');
if cleartext = nil then
  raise Exception.Create('Error Reading Input File. ' + GetErrorMessage);
crypted := BIO_new_file(PChar(CryptedFile), 'wb');
if crypted = nil then
  raise Exception.Create('Error Reading Output File. ' + GetErrorMessage);

keysize := RSA_size(rsa);

// Should be free if exception is raised
rsa_in := OPENSSL_malloc(keysize * 2);
rsa_out := OPENSSL_malloc(keysize);

// Read the input data
rsa_inlen := BIO_read(cleartext, rsa_in, keysize * 2);
if rsa_inlen <= 0 then
  raise Exception.Create('Error reading input Data.');
rsa_outlen := RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, padding);
if rsa_outlen <= 0 then
  raise Exception.Create('RSA operation error. ' + GetErrorMessage);

BIO_write(crypted, rsa_out, rsa_outlen);
RSA_free(rsa);
BIO_free(cleartext);
BIO_free_all(crypted);
if rsa_in <> nil then
  OPENSSL_free(rsa_in);
if rsa_out <> nil then
  OPENSSL_free(rsa_out);
end;
```
