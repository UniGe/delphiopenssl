# Delphi import unit per OpenSSL DLL

## How to extract a PKCS#7 envelop content
## _Estrazione del contenuto di una busta PKCS#7_

_Richiede [OpenSSLUtils.pas](OpenSSLUtils.pas)_

Require [OpenSSLUtils.pas](OpenSSLUtils.pas)

```
program PKCS7;

uses OpenSSLUtils;

var
  infile, outfile: String;

procedure ExtractPKCS7File(InFilename, OutFilename: String);
var
  reader: TPKCS7;
begin
reader := TPKCS7.Create;
reader.Open(InFilename);
reader.SaveContent(OutFileName);
reader.Free;
end;

begin
AppStartup;   // init crypto function
infile := 'envelope.pdf.p7m';
outfile := 'content.pdf';
ExtractPKCS7File(infile, outfile);
end.
```

_Ecco il frammento di OpenSSLUtils.pas_

This is the OpenSSLUtils.pas snippet

```
// Open a PKCS7 file
procedure TPKCS7.Open(Filename: string);
var
  p7file: pBIO;
  objectType: integer;
begin
p7file := BIO_new(BIO_s_file());
if p7file = nil then
  raise EOpenSSL.Create('Unable to create a file handle.');
BIO_read_filename(p7file, PChar(Filename));
if (fEncoding = auto) or (fEncoding = DER) then
  begin
  fPkcs7 := d2i_PKCS7_bio(p7file, nil);
  if (fPkcs7 = nil) and (fEncoding = auto) then
    BIO_reset(p7file);
  end;
if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = PEM) then
  begin
  fPkcs7 := PEM_read_bio_PKCS7(p7file, nil, nil, nil);
  if (fPkcs7 = nil) and (fEncoding = auto) then
    BIO_reset(p7file);
  end;
if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = SMIME) then
  begin
  fPkcs7 := SMIME_read_PKCS7(p7file, fDetachedData);  // &indata ????
  end;
if fPkcs7 = nil then
  raise EOpenSSL.Create('Unable to read PKCS7 file');
if p7file <> nil then
  BIO_free(p7file);
objectType := OBJ_obj2nid(fPkcs7.asn1_type);
case objectType of
  NID_pkcs7_signed: fCerts := fPkcs7.sign.cert;
  NID_pkcs7_signedAndEnveloped: fCerts := fPkcs7.signed_and_enveloped.cert;
  end;
end;

procedure TPKCS7.SaveContent(Filename: String);
var
  p7bio, contentfile: pBIO;
  sinfos: pSTACK_OFPKCS7_SIGNER_INFO;
  i: integer;
  buffer: array [0..4096] of char;
begin
if fPkcs7 = nil then
  raise EOpenSSL.Create('No PKCS7 content.');
if OBJ_obj2nid(fPkcs7.asn1_type) <> NID_pkcs7_signed then
  raise EOpenSSL.Create('Wrong PKCS7 format.');
if (PKCS7_get_detached(fPkcs7) <> nil)
    and (fDetachedData = nil) then
  raise EOpenSSL.Create('PKCS7 has no content.');
sinfos := PKCS7_get_signer_info(fPkcs7);
if (sinfos = nil) or (sk_num(sinfos) = 0) then
  raise EOpenSSL.Create('No signature data.');
contentfile := BIO_new(BIO_s_file());
if BIO_write_filename(contentfile, PChar(Filename)) <= 0 then
  raise EOpenSSL.Create('Error creating output file.');
p7bio := PKCS7_dataInit(fPkcs7, fDetachedData);
repeat
  i := BIO_read(p7bio, @buffer, SizeOf(buffer));
  if i > 0 then
    BIO_write(contentfile, @buffer, i);
until i <= 0;

if fDetachedData <> nil then
  BIO_pop(p7bio);
BIO_free_all(p7bio);
BIO_free(contentfile);
end;
```

