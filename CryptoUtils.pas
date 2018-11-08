(******************************************************************************
 Version 0.3, 2008-04-22
 Copyright (C) 2002-2007, Marco Ferrante.
 2002-2006, CSITA - Università di Genova (IT).
 2007-2008, DISI - Università di Genova (IT).
 http://www.disi.unige.it/person/FerranteM/delphiopenssl/

 Require libeay32.pas >= 0.7a, 2006-01-16

 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 ******************************************************************************)
unit CryptoUtils;

interface

uses SysUtils, libeay32, Classes;

type
  // Function returning a string passphrase to decrypt keys
  TPasswordCallback = function(): string;

  // OpenSSL exception
  ELibeay = class(Exception)
    protected
      fErrorCode: integer;
      fErrorMessage: string;
    public
      constructor Create(Msg: string);
      property LibeayCode: integer read fErrorCode;
      property LibeayMessage: string read fErrorMessage;
  end;

// Init OpenSSL environment: require before any OpenSSL function call
procedure InitOpenSSL;
// Cleanup environment
procedure FreeOpenSSL;
// Return last error message
function GetErrorMessage: string;
// Return libeay32.dll version
function Version: string; overload;
function Version(Verbose: boolean): string; overload;

// Set file for random data
procedure SetSeedFile(Filename: TFilename);

// Create a new BIO (I/O abstraction) for reading file
function CreateFileInputBio(AFileName: TFileName): pBIO;
// Create a new BIO (I/O abstraction) for writing file
function CreateFileOutputBio(AFileName: TFileName; Append: boolean): pBIO;
// Create a new input BIO from string
function CreateStringInputBio(content: string): pBIO;
// Create a new memory output BIO
function CreateMemoryOutputBio(): pBIO;
// Convert a memory output BIO
function GetStringFromBio(MemoryBio: pBIO): string; overload;
function GetStringFromBio(MemoryBio: pBIO; HexEncoded: boolean): string; overload;

// Read a public key.
function GetPublicKey(KeyBio: pBIO; Encoding: integer): pEVP_PKEY;

// Read a private key.
function GetPrivateKey(KeyBio: pBIO; Encoding: integer; Password: string): pEVP_PKEY;

// Return a list of available cipher
function AvailableCipher: TStrings;

// Generate a RSA keypair
function GenerateRSAKey(KeyLength: word; Exponent: integer;
    Progress: TProgressCallbackFunction; CBArgs: pointer): pEVP_PKEY;

// Encrypt using a RSA key
procedure RSAEncrypt(Key: pEVP_PKEY; Cleartext, Crypted: pBIO); overload;
procedure RSAEncrypt(Key: pEVP_PKEY; Cleartext, Crypted: pBIO; Padding: integer); overload;

// Decrypt using RSA key
procedure RSADecrypt(Key: pEVP_PKEY; Crypted, Cleartext: pBIO); overload;
procedure RSADecrypt(Key: pEVP_PKEY; Crypted, Cleartext: pBIO; Padding: integer); overload;

implementation

var
  RndSeedFile: string;
  DefaultRSACryptPadding: integer = RSA_PKCS1_PADDING;

constructor ELibeay.Create(Msg: string);
var
  ErrMsg: array [0..160] of char;
  errcode: integer;
begin
inherited Create(Msg);
fErrorCode := ERR_peek_error;
fErrorMessage := '';
repeat
  errcode := ERR_get_error;
  if errcode > 0 then
    begin
    ERR_error_string(errcode, @ErrMsg);
    if length(fErrorMessage) > 0 then
      fErrorMessage := #13#10 + fErrorMessage;
    fErrorMessage := StrPas(@ErrMsg) + fErrorMessage;
    end;
until errcode = 0;
end;

{
  Create a new BIO (I/O abstraction) from file
  for read
  Parameters:
    AFilename: a file name
    ForWriting: true if file should be open in write mode
  Return:
    a BIO pointer
  See http://www.openssl.org/docs/crypto/bio.html
}
function CreateFileInputBio(AFileName: TFileName): pBIO;
begin
result := BIO_new_file(PChar(AFileName), 'rb');
if result = nil then
  raise ELibeay.Create('Error accessing file ' + AFileName
      + ' on reading. ' + GetErrorMessage);
end;

{
  Create a new BIO (I/O abstraction) from file
  for write
  Parameters:
    AFilename: a file name
    Append: true if file should be open in append mode
  Return:
    a BIO pointer
  See http://www.openssl.org/docs/crypto/bio.html
}
function CreateFileOutputBio(AFileName: TFileName; Append: boolean): pBIO;
var
  mode: PChar;
begin
if Append then
  mode := 'ab'
else
  mode := 'wb';
result := BIO_new_file(PChar(AFileName), mode);
if result = nil then
  raise ELibeay.Create('Error accessing file ' + AFileName
      + ' for writing. ' + GetErrorMessage);
end;

{
  Create a new BIO from a read only string
  Parameters:
    content: string content
  Return:
    a BIO pointer
}
function CreateStringInputBio(Content: string): pBIO;
begin
result := BIO_new_mem_buf(PChar(content), -1);
end;

{
  Create a new BIO as memory buffer.
  To obtain string result, see GetStringFromBio()
  Return:
    a BIO pointer
}
function CreateMemoryOutputBio(): pBIO;
begin
result := BIO_new(BIO_s_mem);
end;

{
  Return a string from an output memory bio
}
function GetStringFromBio(MemoryBio: pBIO): string;
begin
result := GetStringFromBio(MemoryBio, false);
end;

function GetStringFromBio(MemoryBio: pBIO; HexEncoded: boolean): string; overload;
var
  buff, hbuff: PChar;
  buffsize: integer;
begin
BIO_flush(MemoryBio);
buffsize := BIO_pending(MemoryBio);
GetMem(buff, buffsize + 1);
if HexEncoded then
  begin
  buffsize := BIO_read(MemoryBio, buff, buffsize);
  GetMem(hbuff, 2 * buffsize + 1);
  BinToHex(buff, hbuff, buffsize);
  result := StrPas(hbuff);
  FreeMem(hbuff);
  end
else
  begin
  buffsize := BIO_read(MemoryBio, buff, buffsize);
  buff[buffsize] := #0;
  result := StrPas(buff);
  end;
FreeMem(buff);
end;

{
  Read a public key.
  Remember to free keybio after reading or on exception.
  Parameters:
    keybio: retrieved using CreateFileBio or CreateMemBio to
         read key from file or memory
    encoding: can be
         FORMAT_ASN1 = 1: DER encoding
         FORMAT_PEM = 3: PEM encoding
         FORMAT_X509 = 509: a PEM encoded X.509 certificate
  Return:
    a public key or raise exception if key cannot be load
}
function GetPublicKey(keybio: pBIO; encoding: integer): pEVP_PKEY;
var
  a: pEVP_PKEY;  // Because d2i_PUBKEY_bio uses a parameter by-reference
  c:  pX509;  // Because PEM_read_ uses a parameter by-reference
  cert: pX509;
begin
a := nil; // Bad initializatioon can cause exception
result := nil;  // To avoid warning during compiling
if keybio = nil then
  raise Exception.Create('No key specified.');
case encoding of
  FORMAT_ASN1:
    result := d2i_PUBKEY_bio(keybio, a);
  FORMAT_PEM:
    result := PEM_read_bio_PUBKEY(keybio, a, nil, nil);
  FORMAT_X509:
    begin
    c := nil; // Bad initializatioon can cause exception
    cert := PEM_read_bio_X509_AUX(keybio, c, nil, nil);
    if cert = nil then
      raise ELibeay.Create('Invalid certificate.');
    result := X509_get_pubkey(cert);
    X509_free(cert);
    end;
  else
    raise Exception.Create('Unsupported key encoding.');
end;
if result = nil then
  raise ELibeay.Create('Unable to load public key.');
end;

{
  Read a private key, asking for password if required.
}
function GetPrivateKeyWithPrompt(keybio: pBIO; encoding: integer;
  PasswordCallback: TPasswordCallback): pEVP_PKEY;
var
  a: pEVP_PKEY;  // Because d2i_PUBKEY_bio uses a parameter by-reference
  p12: pPKCS12;
  pw: PChar;
  cert: pX509;  // Dummy, only for PKCS12_parse
  cacerts: pSTACK_OFX509;  // Dummy, only for PKCS12_parse

  // Callback for encrypted private key
  function cb(buffer: PChar; blength: integer;
      verify: integer; data: pointer): integer; cdecl;
  var
    Passphrase: String;
  begin
  result := 0;
  if (data = nil) then
    exit;
  Passphrase := PasswordCallback();
  if Passphrase <> '' then
    begin
    StrPCopy(buffer, Passphrase);  // TODO: length check
    result := Length(Passphrase);
    end
  end;

begin
a := nil; // Bad initialization can cause exception
result := nil;  // To avoid warning during compiling
if keybio = nil then
  raise Exception.Create('No key specified.');
case encoding of
  FORMAT_ASN1:
    result := d2i_PrivateKey_bio(keybio, a);
  FORMAT_PEM:
    result := PEM_read_bio_PrivateKey(keybio, a, @cb, nil);
  FORMAT_PKCS12:
    begin
    p12 := d2i_PKCS12_bio(keybio, nil);
    cert := nil; // Dummy
    cacerts := nil; // Dummy
    PKCS12_parse(p12, pw, result, cert, cacerts);

    PKCS12_free(p12);
    end;
  else
    raise Exception.Create('Unsupported key encoding.');
end;
if result = nil then
  raise ELibeay.Create('Unable to load private key. ' + GetErrorMessage);
end;

{
  Read a private key.
  Remember to free keybio after reading or on exception.
  Parameters:
    KeyBio: retrieved using CreateFileBio or CreateMemBio to
         read key from file or memory
    Encoding: can be
         FORMAT_ASN1 = 1: DER encoding
         FORMAT_PEM = 3: PEM encoding
         FORMAT_PKCS12 = 5: PKCS#12 package
    Password:
         encryption passpharase for the key; for cleartext key,
         pass an empty string
  Return:
    a public key or raise exception if key cannot be load
}
function GetPrivateKey(KeyBio: pBIO; Encoding: integer; Password: string): pEVP_PKEY;
var
  a: pEVP_PKEY;  // Because d2i_PUBKEY_bio uses a parameter by-reference
  p12: pPKCS12;
  pw: PChar;
  cert: pX509;  // Dummy, only for PKCS12_parse
  cacerts: pSTACK_OFX509;  // Dummy, only for PKCS12_parse

begin
a := nil; // Bad initializatioon can cause exception
result := nil;  // To avoid warning during compiling
if keybio = nil then
  raise Exception.Create('No key specified.');
if password = '' then
  pw := nil
else
  pw := PChar(password);
case encoding of
  FORMAT_ASN1:
    result := d2i_PrivateKey_bio(keybio, a);
  FORMAT_PEM:
    result := PEM_read_bio_PrivateKey(keybio, a, nil, pw);
  FORMAT_PKCS12:
    begin
    p12 := d2i_PKCS12_bio(keybio, nil);
    cert := nil; // Dummy
    cacerts := nil; // Dummy
    PKCS12_parse(p12, pw, result, cert, cacerts);

    PKCS12_free(p12);

    end;
  else
    raise Exception.Create('Unsupported key encoding.');
end;
if result = nil then
  raise ELibeay.Create('Unable to load private key. ' + GetErrorMessage);
end;

{
  Return a list of (certainly) available cipher. Due to OpenSSL design,
  more ciphers can be available without "autodiscover" capability to find them.
  Return names are compatible with EVP_get_cipherbyname function.

  Implementation is not so smart, but is as OpenSSL does.
}
function AvailableCipher: TStrings;
const
  testnames: array [0..95] of string = ('null', 'base64',
      'aes-128-ecb', 'aes-128-cbc', 'aes-128-cfb',
      'aes-128-cfb1', 'aes-128-cfb8', 'aes-128-ofb', 'aes-128-ctr', 'AES128',
      'aes-192-ecb', 'aes-192-cbc', 'aes-192-cfb', 'aes-192-cfb1',
      'aes-192-cfb8', 'aes-192-ofb', 'aes-192-ctr', 'AES192', 'aes-256-ecb',
      'aes-256-cbc', 'aes-256-cfb', 'aes-256-cfb1', 'aes-256-cfb8',
      'aes-256-ofb', 'aes-256-ctr', 'AES256',
      'des-cfb', 'des-cfb1', 'des-cfb8', 'des-ede-cfb', 'des-ede3-cfb',
      'des-ofb', 'des-ede-ofb', 'des-ede3-ofb', 'desx-cbc', 'DESX', 'des-cbc',
      'DES', 'des-ede-cbc', 'des-ede3-cbc', 'DES3', 'des-ecb', 'des-ede',
      'des-ede3',
      'RC4', 'rc4-40',
      'idea-ecb', 'idea-cfb', 'idea-ofb', 'idea-cbc', 'IDEA',
      'rc2-ecb', 'rc2-cfb', 'rc2-ofb', 'rc2-cbc', 'rc2-40-cbc', 'rc2-64-cbc', 'RC2',
      'bf-ecb', 'bf-cfb', 'bf-ofb', 'bf-cbc', 'BF', 'blowfish',
      'cast5-ecb', 'cast5-cfb', 'cast5-ofb', 'cast5-cbc', 'CAST', 'CAST-cbc',
      'rc5-32-12-16-ecb', 'rc5-32-12-16-cfb', 'rc5-32-12-16-ofb', 'rc5-32-12-16-cbc', 'RC5',
      'camellia-128-ecb', 'camellia-128-cbc', 'camellia-128-cfb', 'camellia-128-cfb1',
      'camellia-128-cfb8', 'camellia-128-ofb', 'CAMELLIA128', 'camellia-192-ecb',
      'camellia-192-cbc', 'camellia-192-cfb', 'camellia-192-cfb1', 'camellia-192-cfb8',
      'camellia-192-ofb', 'CAMELLIA192', 'camellia-256-ecb', 'camellia-256-cbc',
      'camellia-256-cfb', 'camellia-256-cfb1', 'camellia-256-cfb8', 'camellia-256-ofb', 'CAMELLIA256'
   );
var
  i: integer;
begin
result := TStringList.Create;
TStringList(result).CaseSensitive := false;
TStringList(result).Sorted := true;
for i := 0 to High(testnames) do
  begin
  if EVP_get_cipherbyname(PChar(testnames[i])) <> nil then
    begin
    result.Add(testnames[i]);
    end;
  end;
end;

{
  Generate a RSA keypair

  Parameters:
    KeyLength:
        modulus size in bit numbers
    Exponent:
        public exponent, an odd number, typically 3, 17 or 65537.
    Cipher:
        cipher for private key.
        If nil, key will be registered in cleartext
    Password:
        cipher password
  Return:
    A key in a pEVP_PKEY structure. Remember to free it.
}
function GenerateRSAKey(KeyLength: word; Exponent: integer;
    Progress: TProgressCallbackFunction; CBArgs: pointer): pEVP_PKEY;
var
  rsa: pRSA;
begin
if @Progress = nil then
  CBArgs := nil;

result := EVP_PKEY_new;
if result = nil then
  raise ELibeay.Create('Key allocation failed.');

// Load a pseudo random file
RAND_load_file(PChar(RndSeedFile), -1);

rsa := RSA_generate_key(KeyLength, Exponent, Progress, CBArgs);
if rsa = nil then
  raise ELibeay.Create('RSA key creation failed.');

if EVP_PKEY_set1_RSA(result, rsa) = 0 then
  begin
  EVP_PKEY_free(result);
  raise ELibeay.Create('RSA key copy failed.');
  end;

if rsa <> nil then
  RSA_free(rsa);
end;

{
  Encrypt a BIO content
  Equivalent to:
    openssl rsautl -encrypt -in CleartextFile -out CryptedFile -inkey KeyFile

  The random number generator must be seeded prior to calling RSAEncrypt.
  Parameters:
    Key:
        A RSA key
    Cleartext:
        A BIO containing clear text or data; data length must be less than
        RSA key size-11 for the PKCS #1 padding modes, less than RSA key size-41
        for RSA_PKCS1_OAEP_PADDING and exactly RSA key size for RSA_NO_PADDING.
        Exceding data will be ignored.
    Crypted:
        A BIO allocated for crypted data (usually binary)
    Padding:
        RSA_PKCS1_PADDING = 1;
        RSA_SSLV23_PADDING = 2;
        RSA_NO_PADDING = 3;
        RSA_PKCS1_OAEP_PADDING = 4;
}
procedure RSAEncrypt(Key: pEVP_PKEY; Cleartext, Crypted: pBIO);
begin
RSAEncrypt(Key, Cleartext, Crypted, DefaultRSACryptPadding);
end;

procedure RSAEncrypt(Key: pEVP_PKEY; Cleartext, Crypted: pBIO; Padding: integer);
var
  rsa: pRSA;
  keysize: integer;
  indata, outdata: pointer;
  indatalen, outdatalen: integer;
begin
if RAND_status = 0 then
  raise Exception.Create('Not enough random data, call RAND_add first.');

rsa := EVP_PKEY_get1_RSA(Key);
if rsa = nil then
  raise ELibeay.Create('Invalid key format.');

keysize := RSA_size(rsa);

// Should be free if exception is raised
indata := OPENSSL_malloc(keysize * 2);
outdata := OPENSSL_malloc(keysize);

// Read the input data
indatalen := BIO_read(cleartext, indata, keysize * 2);
if indatalen <= 0 then
  raise ELibeay.Create('Error reading input Data.');
outdatalen := RSA_public_encrypt(indatalen, indata, outdata, rsa, padding);
if outdatalen < 0 then
  begin
  if indata <> nil then
    OPENSSL_free(indata);
  raise ELibeay.Create('RSA operation error.');
  end;

BIO_write(crypted, outdata, outdatalen);
RSA_free(rsa);
if indata <> nil then
  OPENSSL_free(indata);
if outdata <> nil then
  OPENSSL_free(outdata);
end;

{
  Decrypt a BIO content using RSA key
  Equivalent to:
    openssl rsautl -decrypt -in cifrato.enc -inkey private.key
  Parameters:
    Key:
        A RSA key
    Crypted:
        A BIO allocated for crypted data (usually binary)
    Cleartext:
        A BIO containing clear text or data
        Pay attention, comparing with RSAEncrypt(), Cleartext and Crypted
        are switch 
    Padding:
        RSA_PKCS1_PADDING = 1;
        RSA_SSLV23_PADDING = 2;
        RSA_NO_PADDING = 3;
        RSA_PKCS1_OAEP_PADDING = 4;
}
procedure RSADecrypt(Key: pEVP_PKEY; Crypted, Cleartext: pBIO);
begin
RSADecrypt(Key, Crypted, Cleartext, DefaultRSACryptPadding);
end;

procedure RSADecrypt(Key: pEVP_PKEY; Crypted, Cleartext: pBIO; padding: integer);
var
  rsa: pRSA;
  keysize, datalen: integer;
  indata, outdata: pointer;
  indatalen, outdatalen: integer;
begin
rsa := EVP_PKEY_get1_RSA(Key);
if rsa = nil then
  raise ELibeay.Create('Invalid key format.');

keysize := RSA_size(rsa);

indata := OPENSSL_malloc(keysize * 2);
outdata := OPENSSL_malloc(keysize);

// Read the input data
BIO_flush(Crypted);
datalen := BIO_pending(Crypted);

indatalen := BIO_read(Crypted, indata, datalen);
if indatalen <= 0 then
  raise ELibeay.Create('Error reading input Data.');
outdatalen := RSA_private_decrypt(indatalen, indata, outdata, rsa, padding);
if outdatalen < 0 then
  begin
  if indata <> nil then
    OPENSSL_free(indata);
  raise ELibeay.Create('RSA operation error.');
  end;

BIO_write(Cleartext, outdata, outdatalen);
RSA_free(rsa);
if indata <> nil then
  OPENSSL_free(indata);
if outdata <> nil then
  OPENSSL_free(outdata);
end;

{
  You must call this procedure before any OpenSSL-related function.
  When you finish, you can clear environment with FreeOpenSSL prodedure.
}
procedure InitOpenSSL;
begin
OpenSSL_add_all_algorithms;
OpenSSL_add_all_ciphers;
OpenSSL_add_all_digests;
ERR_load_crypto_strings;
RndSeedFile := '';
end;

{
  Cleanup environment and release memory.
}
procedure FreeOpenSSL;
begin
EVP_cleanup;
end;

{
  Return last error message and remove it from error stack.
  If not error is present, return a empty string.
}
function GetErrorMessage: string;
var
  ErrMsg: array [0..160] of char;
  errcode: integer;
begin
result := '';
errcode := ERR_get_error;
if errcode > 0 then
  begin
  ERR_error_string(errcode, @ErrMsg);
  result := StrPas(@ErrMsg);
  end;
end;

function Version: string; overload;
begin
result := Version(false);
end;

// Return libeay32.dll version
function Version(Verbose: boolean): string;
var
  v: cardinal;
  s: PChar;
begin
v := SSLeay;
result := IntToHex(v, 9);
if Verbose then
  begin
  s := SSLeay_version(_SSLEAY_CFLAGS);
  result := result + ' (' + Trim(s) + ')';
  end;
end;

procedure SetSeedFile(Filename: TFilename);
begin
RndSeedFile := Filename;
end;

{
  Uncomment to enable automatic initialization and finalization
initialization
  InitOpenSSL;

finalization
  FreeOpenSSL;
}
end.
