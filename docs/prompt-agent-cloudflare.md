# Prompt dla agenta obsługującego Cloudflare

Do wklejenia agentowi, który ma dostęp do konta Cloudflare z prawem zapisu.
Prompt jest samodzielny: nie zakłada wiedzy z rozmowy, w której powstał.

Trzy zadania, każde niezależne. Agent może wykonać je w jednej sesji.

---

```
Masz dostep do konta Cloudflare "Aurabroker@gmail.com's Account",
account_id: 1f52c869d091ebf55a2d1789dad4842d

Wykonaj trzy zadania opisane nizej. Nie rob niczego poza nimi.

## ZASADY BEZWZGLEDNE

1. NIE wlaczaj HSTS preload nigdzie i w zadnej formie. Jest praktycznie
   nieodwracalne.
2. NIE dodawaj tras Workerow dla zadnego hosta poza jednym wskazanym
   w zadaniu 1.
3. NIE dotykaj Workera "security-monitor" ani jego namespace'u KV
   (MONITOR_STATE). To dziala i ma dzialac dalej.
4. NIE usuwaj ani nie nadpisuj istniejacych rekordow DNS. Wolno wyłącznie
   dodawac nowe. Jesli rekord o tej samej nazwie juz istnieje, pomin go
   i zglos to w raporcie.
5. Przed kazda zmiana wypisz, co dokladnie zamierzasz zrobic. Po kazdej
   zmianie potwierdz wynik.
6. Jesli cokolwiek nie zgadza sie z opisem ponizej, zatrzymaj sie i zapytaj,
   zamiast improwizowac.

## ZADANIE 1: trasa Workera dla hosta pilotazowego

Worker "security-headers" jest wgrany na konto, ale nie ma przypisanej
zadnej trasy, wiec nie obsluguje ruchu. Przypisz mu dokladnie jedna trase:

  wzorzec:  rozwodochota.pl/*
  strefa:   rozwodochota.pl  (zone_id: d6e1b8b7f0e448ee513d66f4dd0adb3c)

Tylko ta jedna. Nie dodawaj www ani zadnej innej domeny.

Kontekst, zebys wiedzial co robisz: ten Worker doklada naglowki
bezpieczenstwa do odpowiedzi. Polityka dla tego hosta jest ustawiona na tryb
obserwacyjny, czyli CSP jest wysylane jako Content-Security-Policy-Report-Only
i niczego nie blokuje.

Po dodaniu trasy zweryfikuj:

  curl -sI https://rozwodochota.pl/

Oczekiwane: obecne Content-Security-Policy-Report-Only, X-Frame-Options: DENY,
Strict-Transport-Security: max-age=300, Permissions-Policy,
X-Content-Type-Options: nosniff.

KRYTYCZNE: naglowka "Content-Security-Policy" BEZ dopisku Report-Only
NIE MOZE byc. Jesli jest, natychmiast usun trase i zglos to.

Sprawdz tez, ze strona nadal sie otwiera i zwraca status 200.

## ZADANIE 2: wymuszenie HTTPS na pieciu strefach

Wlacz opcje "Always Use HTTPS" (SSL/TLS -> Edge Certificates) na strefach:

  auraconsulting.pl   6340a33ebc8e513dd8cf5eae4206439d
  grupowe.pro         12f18f72e0a2482af8b3bb210beda473
  gwarancje.pro       68be8eb68ba0ea4cb42d3d12d9442746
  idzik.org.pl        c31b69e84c156d84a1a7520ebe9e2a79
  beautypolisa.eu     c61673ea4d248d75bc769b65c65af3a7

Te piec domen nie przekierowuje dzis ruchu z portu 80 na HTTPS. Pozostalych
stref na koncie NIE dotykaj, tam juz to dziala.

Weryfikacja per domena:

  curl -sI http://DOMENA/ | head -3

Oczekiwane: status 301 i naglowek Location zaczynajacy sie od https://

## ZADANIE 3: rekordy DMARC

Cel: zadna z domen nie ma dzis rekordu DMARC, wiec kazdy moze wyslac maila
podszywajacego sie pod te domeny. Dotyczy to takze domen, ktore nie obsluguja
poczty, bo podszycie sie nie wymaga rekordow MX.

KROK 3A. Dla kazdej strefy na koncie sprawdz i wypisz w tabeli:
  - czy istnieje rekord TXT o nazwie _dmarc.DOMENA
  - czy istnieje rekord TXT na korzeniu zaczynajacy sie od "v=spf1"
  - czy istnieja rekordy MX
  - czy istnieja rekordy z "._domainkey" w nazwie (DKIM)

Pokaz mi te tabele PRZED dodaniem czegokolwiek.

KROK 3B. Klasyfikacja. Domena nalezy do grupy WYSYLAJACEJ, jesli ma rekordy MX
albo jest jedna z tych dwoch, niezaleznie od MX:

  auraconsulting.pl
  beautypolisa.eu

Beautypolisa.eu wysyla poczte przez Resend, wiec ostra polityka zablokowalaby
wlasna wysylke. Pozostale domeny naleza do grupy NIEWYSYLAJACEJ.

KROK 3C. Dodaj rekordy TXT.

Grupa NIEWYSYLAJACA, dla kazdej takiej domeny:

  typ:    TXT
  nazwa:  _dmarc
  tresc:  v=DMARC1; p=reject

Grupa WYSYLAJACA, dla kazdej takiej domeny:

  typ:    TXT
  nazwa:  _dmarc
  tresc:  v=DMARC1; p=none; rua=mailto:dmarc@auraconsulting.pl; fo=1

p=none niczego nie blokuje, tylko zbiera raporty. Zaostrzymy to pozniej,
po przejrzeniu raportow.

KROK 3D. Autoryzacja raportow miedzy domenami.

Adres raportowy jest na auraconsulting.pl, a rekord DMARC beautypolisa.eu
na niej wskazuje. Standard wymaga wtedy zgody domeny odbierajacej raporty.
Bez tego rekordu Gmail i Microsoft nie wysla raportow.

W STREFIE auraconsulting.pl dodaj:

  typ:    TXT
  nazwa:  beautypolisa.eu._report._dmarc
  tresc:  v=DMARC1

Taki rekord potrzebny jest dla kazdej domeny z grupy WYSYLAJACEJ innej niz
auraconsulting.pl. Jesli zaklasyfikowales tam wiecej domen, dodaj analogiczny
rekord dla kazdej z nich.

KROK 3E. SPF, tylko warunkowo.

Dla domen z grupy NIEWYSYLAJACEJ, ktore JEDNOCZESNIE nie maja zadnego rekordu
MX ANI zadnego istniejacego rekordu SPF, dodaj:

  typ:    TXT
  nazwa:  @
  tresc:  v=spf1 -all

Jesli domena ma MX albo ma juz SPF, POMIN ja i zglos w raporcie. Dodanie
"v=spf1 -all" do domeny, ktora realnie wysyla poczte, zablokuje ta wysylke.

## RAPORT KONCOWY

Na koniec podaj:

1. Czy trasa Workera zostala dodana i co zwrocil curl na naglowkach.
2. Liste stref, na ktorych wlaczono Always Use HTTPS, wraz z wynikiem
   weryfikacji przekierowania.
3. Tabele: domena, grupa (wysylajaca / niewysylajaca), dodany rekord DMARC,
   dodany SPF albo powod pominiecia.
4. Wszystko, co pominales i dlaczego.
5. Wszystko, co wygladalo inaczej, niz opisuje ten prompt.
```

---

## Czego świadomie nie ma w tym promptcie

- **Zmiana zakresu tokenu API.** Tokeny żyją w profilu użytkownika, nie na
  koncie, więc agent działający tokenem nie nadaje sobie uprawnień. Token
  monitora potrzebuje `Zone → Zone → Read`, `Zone → DNS → Read` oraz
  `Zone → SSL and Certificates → Read`, z zasobami ustawionymi na
  `Include → All zones`. To robi człowiek w https://dash.cloudflare.com/profile/api-tokens
- **Podnoszenie HSTS.** Na hoście pilotażowym `max-age` wynosi celowo
  300 sekund. Podnosi się go schodkowo, po potwierdzeniu, że wszystkie
  subdomeny działają po https, i to osobną decyzją.
- **Przełączenie CSP na tryb egzekwowania.** Wymaga przejrzenia raportów
  z 7 do 14 dni i zmiany trybu nonce'a. Osobny etap, opisany w
  `workers/security-headers/README.md`.
- **Kolejne hosty w warstwie nagłówków.** Dopiero po domknięciu pilotażu.
