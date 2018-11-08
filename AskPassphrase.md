# Delphi import unit per OpenSSL DLL

## Ask for private key passphrase with callback</h2>

Require [libeay32.pas](libeay32.pas)

```
(******************************************************************************
 Author: Marco Ferrante
 Copyright (C) 2002-2012, CSITA - Università di Genova (IT).
 http://www.csita.unige.it/
 ******************************************************************************)
unit main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, libeay32, StdCtrls;

type
  {
    Must return passphrase
  }
  TAskPassphraseEvent = procedure(var Passphrase: String) of object;

  TMainForm = class(TForm)
    Button1: TButton;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
    fAskPassphrase: TAskPassphraseEvent;
    procedure InitOpenSSL;
    procedure FreeOpenSSL;
    procedure AskPassphrase(var Passphrase: String);
    function ReadPrivateKey(AFileName: TFileName): pEVP_PKEY;
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}
{
  Return last error message
}
function GetErrorMessage: string;
var
  ErrMsg: array [0..160] of char;
begin
ERR_error_string(ERR_get_error, @ErrMsg);
result := StrPas(@ErrMsg);
end;

{
  You must call this procedure before any OpenSSL-related function.
  When you finish, you can clear environment with FreeOpenSSL prodedure.
}
procedure TMainForm.InitOpenSSL;
begin
OpenSSL_add_all_algorithms;
OpenSSL_add_all_ciphers;
OpenSSL_add_all_digests;
ERR_load_crypto_strings;
end;

{
  Cleanup environment and release memory.
}
procedure TMainForm.FreeOpenSSL;
begin
EVP_cleanup;
end;

{
  Open a dialog to ask for passphrase if required.
}
procedure TMainForm.AskPassphrase(var Passphrase: String);
begin
Passphrase := 'bar';  // Dummy example value
end;

{
  Read a private key, asking for password if required.
}
function TMainForm.ReadPrivateKey(AFileName: TFileName): pEVP_PKEY;
var
  keyfile: pBIO;
  foo: pEVP_PKEY;  // Because PEM_read_bio_PrivateKey uses parameters by-reference;

  // Callback for encrypted private key
  function cb(buffer: PChar; blength: integer;
      verify: integer; data: pointer): integer; cdecl;
  var
    Passphrase: String;
  begin
  result := 0;
  if (data = nil) or not(TObject(data) is TMainForm) then
    exit;
  if not Assigned(TMainForm(data).fAskPassphrase) then
    exit;
  TMainForm(data).fAskPassphrase(Passphrase);
  if Passphrase <> '' then
    begin
    StrPCopy(buffer, Passphrase);  // TODO: length check
    result := Length(Passphrase);
    end
  end;

begin
foo := nil;
keyfile := BIO_new(BIO_s_file());
BIO_read_filename(keyfile, PChar(AFilename));
result := PEM_read_bio_PrivateKey(keyfile, foo, @cb, self);
if result = nil then
  raise Exception.Create('Unable to read private key. ' + GetErrorMessage);
end;

{
  Main procedure: when you press button, private key will be load
}
procedure TMainForm.Button1Click(Sender: TObject);
var
  key: pEVP_PKEY;
begin
fAskPassphrase := AskPassphrase;
InitOpenSSL;
key := ReadPrivateKey('foo.key');
FreeOpenSSL
end;

end.
```

