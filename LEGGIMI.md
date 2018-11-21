# Delphi import unit per OpenSSL DLL
(questa è la copia del vecchio sito https://www.disi.unige.it/person/FerranteM/delphiopenssl/)
## Questo repository non è più mantenuto, potete trovarne una versione aggiornata qui: https://github.com/zizzo81/delphiopenssl

[English version](README.md)

[OpenSSL](http://www.openssl.org/) un progetto
collaborativo per lo sviluppo di un toolkit che implementi 
SSL/TLS rilasciato sotto una licenza open source simil-BSD.<br>
Per utilizzare OpenSSL su sistemi Microsoft Windows a 32 bit,
occorre procurarsi una copia delle DDL dal [Progetto GNU Win32](http://gnuwin32.sourceforge.net/)
(la versione per cui è stata sviluppata questa unit) o dal
modulo del progetto wget sul sito [SunSite](http://ftp.sunsite.dk/projects/wget/windows/ssllibs.zip).

## Borland Delphi e OpenSSL
Le librerie di OpenSSL possono essere utilizzate da Borland Delphi
invocando le DLL.

Il toolkit OpenSSL è composto di due parti: `libssl`, che implementa SSLv2/v3
e TLS per le comunicazioni di rete e `libcrypto`, che fornisce i servizi
crittografici, le funzioni di hash, il supporto per le strutture
dati tipo ASN.1 e la gestione dei certificati X.509.

Per l'uso delle funzioni di rete per la comunicazione SSLv2/v3
e TLS, un buon modulo è disponibile nei componenti di [Indy](http://www.nevrona.com/Indy/).

Per la gestione dei certificati X.509, [CSITA](http://www.cedia.unige.it/) ha scritto una unit
per l'importazione delle funzioni specifiche.

## File necessari

- [Gnu Win32](http://gnuwin32.sourceforge.net/packages/openssl.htm) libeay32.dll
  - DLL di OpenSSL. La unit è stata sviluppata per la versione 0.9.6b. Sembra funzionare anche la versione 0.9.6g compilata da [Intelicom](http://www.intelicom.si/) per il progetto Indy;
- [libeay32.pas v. 0.7m](libeay32.pas)
  - Prototipi delle funzioni della DLL. Nella unit non sono definiti tutti i prototipi del migliaio di funzioni esportate della DLL; in particolare non sono presenti quelli che utilizzano parametri _file pointer_ stile C;
  * Novità della versione 0.7m del 05/11/2010
    - corretti erroi e bug
    - aggiunto il supporto per le funzioni PCKS#8 (contributo di Luis Carrasco - Bambu Code, Mexico)
    - ridefinizione di `PChar` come `PCharacter` per gestire i tipi `PChar` e `PAnsiChar`
  * Novità della versione 0.7d del 12/15/2006
    - corretti erroi e bug
    - rimosse le funzioni `EVP_MD_size` and `EVP_MD_CTX_size`: non sono definite nella DLL e gestiscono i parametri in mdo dipendente dalla versione.
    - aggiunte le funzioni `BIGNUM`
    - tra le versioni 0.9.6h e 0.9.7, la funzione `OpenSSL_add_all_algorithms` è stata divisa in due distinte funzioni. Le informazioni sono sul sito http://www.openssl.org/news/changelog.html In questa versione della unit, OpenSSL_add_all_algorithms è diventato un wrapper che carica dinamicamente la versione corretta.
  * Novità della versione 0.7 del 09/14/2006
    - bug fix (grazie a M. Hlavac e R. Tamme)
    - funzioni di gestione della memoria
    - funzioni di gestione diretta dei file
  * Novità della versione 0.6 del 07/15/2003
    - corrette alcuni tipi record (`EVP_MD`, `EVP_MD_CTX`, ecc...)
    - definiti nuovi prototipi
  * Novità della versione 0.4 del 03/17/2003
    - rinominata libeay32.pas)
    - corretti alcuni piccoli bug)
    - definiti diversi nuovi prototipi
- [OpenSSLUtils.pas v. 0.5](OpenSSLUtils.pas)
  - Alcune classi e funzioni ausiliarie; questa unit è un "esercizio tecnologico" e non può essere utilizzata in un ambiente di produzione.
  * Nuova versione 0.5, 01/06/2010
    - Grazie a Pablo Romero (Cordoba, Argentina) ora compila su Delphi 2006, 2007, 2009 e 2010
  * Nuovi esempi della versione 0.3 del 24/03/2003
    - nuova classe TPKCS7 per la lettura delle buste PCKS#7
    - nuova classe TX509Certificate per la verifica dei certificati X.509
    - alcune nuove funzioni

La documentazione delle funzioni &egrave; disponibile nel pacchetto dei sorgenti di
OpenSSL.

## Esempi
- [Leggere la versione della DLL](example1.md)
- [Calcolare il digest SHA1](example2.md)
- [Generare una coppia di chiavi RSA (codice in OpenSSLUtils)](example3.md)
- [Firmare in formato S/MIME un messaggio (codice in OpenSSLUtils)](example4.md)
- [Estrazione del contenuto di una busta PKCS#7 (codice in OpenSSLUtils)](example5.md)
- [Verifica di una busta PKCS#7 (codice in OpenSSLUtils)](example6.md)
- [Caricare una chiave privata, con richiesta di passphrase via callback.](AskPassphrase.md)
- [Cifrare un file con una chiave privata RSA.](RSAEncrypt.md)
- [firma RSA+MD5](RSAMD5sig.md)
- *Nuovo* [applicazione decreto Ministero dell'Economia e delle Finanze 24 giugno 2004](decreto24062004.md)

## Comments
Suggerimenti, commenti e contributi sono apprezzati. Per sapere [chi la sta utilizzando](users.md).
