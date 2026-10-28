# 👁️ LoginEye - Detecție Intruși la Autentificarea Windows

**LoginEye** este o aplicație de securitate de fundal (*background process*) pentru Windows, concepută pentru a captura automat o fotografie cu camera web de fiecare dată când cineva încearcă să acceseze laptopul.

- Dacă parola introdusă este **greșită**, face o poză marcată vizibil cu **`[ FAIL ]`** (pe fundal roșu), data, ora și contul vizat.
- Dacă parola este **corectă**, face o poză marcată cu **`[ PASS ]`** (pe fundal verde) în momentul deblocării/logării.
- **100% Silențios**: Funcționează complet în fundal, fără ferestre deschise, fără interfață grafică și fără iconițe în taskbar/tray.
- **Pornire automată la pornirea Windows**: Se configurează în Windows Task Scheduler cu privilegii de sistem pentru a supraveghea ecranul de blocare și autentificarea.

---

## 📸 Exemple de Marcaj pe Fotografii

Fiecare fotografie salvată are aplicat un banner semi-transparent în partea de sus și jos:
- **Badge mare colorat**: `[ FAIL ]` (roșu aprins) sau `[ PASS ]` (verde aprins)
- **Data și Ora exactă**: `2026-10-28 12:30:15`
- **Detalii autentificare**: Numele contului încercat (`Account: ...`), numele laptopului (`Device: ...`) și motivul declanșării.

Fotografiile sunt stocate automat în folderul:
```
c:\Stocare\GithubRepos\logineye\captures\
```
Format fișiere: `FAIL_YYYYMMDD_HHMMSS.jpg` / `PASS_YYYYMMDD_HHMMSS.jpg`

---

## 🚀 Instalare Rapidă (1-Click)

1. Deschide folderul aplicației (`c:\Stocare\GithubRepos\logineye\`).
2. Fă dublu-click pe fișierul **`install.bat`**.
3. Acceptă promptul **UAC (Run as Administrator)**.

Scriptul de instalare va realiza automat:
1. Activează politicile de audit Windows pentru evenimente de autentificare (`auditpol` pentru Event ID 4625 - parolă greșită și Event ID 4624 - autentificare reușită).
2. Înregistrează sarcinile planificate în **Windows Task Scheduler**:
   - `LoginEye_Daemon`: Rulează automat la pornirea sistemului și la logare cu privilegii ridicate.
   - `LoginEye_OnFailedLogin`: Declanșare imediată pe baza Evenimentului de Securitate 4625 (parolă eșuată).
3. Pornește imediat monitorizarea în fundal.

---

## 🧪 Cum se Testează

### Test 1: Test Rapid al Camerei și Marcajului
Fă dublu-click pe **`test_camera.bat`**.
- Acesta va inițializa camera, va captura o poză de test cu **PASS** și una cu **FAIL**, și va deschide automat folderul `captures/` pentru a le vedea.

### Test 2: Test Real pe Ecranul de Blocare (Lock Screen)
1. Blochează ecranul apăsând combinația de taste: **`Windows + L`**.
2. Introdu intenționat o **parolă greșită** și apasă Enter:
   - Camera web se va deschide pentru o fracțiune de secundă și va face poza intruzivă marcată cu **FAIL**.
3. Introdu **parola corectă** și intră în Windows:
   - Camera web va face poza legitimă marcată cu **PASS**.
4. Rulează **`view_captures.bat`** pentru a vedea pozele salvate!

---

## 📁 Structura Proiectului

```
logineye/
│
├── logineye.exe        # Executabilul compilat independent (fără consolă, silențios)
├── main.py             # Punctul de intrare Python
│
├── src/
│   ├── camera.py       # Interfața cu camera web (DirectShow, auto-expunere, eliberare rapidă)
│   ├── stamper.py      # Generarea bannerelor grafice PASS / FAIL, timestamp și metadate
│   ├── event_watcher.py# Monitorizare Windows Session (WTS) și Windows Security Event Log (4625)
│   ├── service.py      # Serviciul principal de fundal și managementul cooldown-ului
│   └── config.py       # Configurații (căi, culori, calitatea JPEG, rotația logurilor)
│
├── captures/           # Aici se salvează fotografiile capturate
├── logs/               # Jurnalul de activitate (logs/logineye.log)
│
├── install.bat         # Instalare automată cu drepturi de Administrator
├── install.ps1         # Scriptul PowerShell de configurare Task Scheduler și auditpol
├── uninstall.bat       # Dezinstalare automată (oprește procesele și șterge sarcinile)
├── test_camera.bat     # Test rapid camera + deschidere folder capturi
├── view_captures.bat   # Deschide direct folderul cu poze
└── build_exe.bat       # Recompilare executabil logineye.exe cu PyInstaller
```

---

## ⚙️ Cum Funcționează Sub Capotă (Arhitectură Tehnică)

1. **Detectarea Parolei Greșite (FAIL)**:
   - La introducerea unei parole incorecte pe ecranul Windows, subsistemul de securitate (LSASS) generează în jurnalul `Security` evenimentul **Audit Failure (Event ID 4625)** cu sub-statutul `0xC000006A` (bad password).
   - Serviciul de fundal `LoginEye` (sau declanșatorul Task Scheduler) interceptează acest eveniment în timp real prin `wevtapi.dll` (Windows Event Log API) și declanșează camera.

2. **Detectarea Parolei Corecte (PASS)**:
   - La introducerea parolei corecte, Windows trimite notificarea de sesiune `WM_WTSSESSION_CHANGE` cu codul `WTS_SESSION_UNLOCK` (0x8) sau `WTS_SESSION_LOGON` (0x5).
   - Acesta notifică procesul instantaneu, realizând fotografia de confirmare a posesorului de drept.

3. **Optimizarea Camerei Web**:
   - Utilizează API-ul Windows DirectShow (`CAP_DSHOW`) pentru pornire accelerată (~0.8s).
   - Execută câteva cadre de pre-încălzire pentru ca senzorul să regleze automat luminozitatea și balansul de alb (evitând pozele întunecate).
   - **Eliberează hardware-ul camerei imediat după captură**: LED-ul camerei nu rămâne aprins, nu consumă bateria laptopului și nu blochează camera pentru alte aplicații (ex: Zoom / Teams / Windows Hello).

4. **Sistem de Cooldown (Anti-Spam)**:
   - Pentru a preveni capturile duplicate dacă un eveniment generează notificări multiple în aceeași secundă, există un filtru inteligent de cooldown de 3 secunde.

---

## 🗑️ Dezinstalare

Pentru a opri serviciul și a elimina sarcinile programate din sistem, rulează:
- **`uninstall.bat`** (cu Run as Administrator).
*(Fotografiile din folderul `captures/` vor fi păstrate în siguranță).*
