# Delphi import unit per OpenSSL DLL

## How to verify a PKCS#7 envelop
## _Verifica di una busta PKCS#7_

_Richiede [OpenSSLUtils.pas](OpenSSLUtils.pas)_

Require [OpenSSLUtils.pas](OpenSSLUtils.pas)

```
program VerifyPKCS7;

uses OpenSSLUtils;

var
  infile: String;
  envelope: TPKCS7;
  CAcerts: array [0..1] of TX509Certificate;

function VerifyPKCS7(p7: TPKCS7): boolean;
begin
result := true;
try
  writeln('Documento firmato da: ' + p7.Certificate[0].Subject);  // print envelope signer
  writeln('Certificato rilasciato da: ' + p7.Certificate[0].Issuer);  // certificate issuer
  if p7.Certificate[0].IsTrusted(CAcerts) then
    writeln('Il certificato è affidabile.');  // signer certificate is trusted
  if (p7.Certificate[0].IsExpired) then
    begin
    if p7.Certificate[0].NotBefore > Time then
      writeln('Il certificato NON è valido.');  // signer cert is expired
    if p7.Certificate[0].NotAfter < Time then
      writeln('Il certificato è scaduto.');  // signer cert is not still valid
    end
  if p7.VerifyData then
    writeln('Il documento è integro.');  // data integrity check passed
except
  on EO: EOpenSSL do
    begin
    writeln('Il file non sembra essere del formato PKCS7 corretto.');  // invalid PKCS#7 file format
    result := false;
    end;
  end;
end;

begin
AppStartup;   // init crypto function
infile := 'envelope.pdf.p7m';
envelope := TPKCS7.Create;
envelope.Open(infile);
CAcerts[0] := TX509Certificate.Create;   // Carica i certificati della CA
CAcerts[0].LoadFromFile('RootCA.crt');   // Load CA certificates
CAcerts[1] := TX509Certificate.Create;
CAcerts[1].LoadFromFile('IntermediateCA.pem');
VerifyPKCS7(envelope);
CAcerts[0].Free;
CAcerts[1].Free;
envelope.Free;
end.
```
