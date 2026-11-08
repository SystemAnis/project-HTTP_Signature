# HTTP Signature Client

Client HTTP in Python che firma il body di una richiesta con **RSA-SHA256** e
valida la firma restituita dal server nell'header `Signature`.

Il progetto nasce come esercitazione ITS ed è organizzato per essere facilmente
leggibile, testabile e sicuro: nessuna chiave privata, URL reale o attempt-code
viene salvato nel repository.

---

## Caratteristiche

- Calcolo dell'header `Digest` con SHA-256 e codifica Base64.
- Firma dell'header `Digest` con chiave privata RSA (PKCS#1 v1.5 + SHA-256).
- Invio della richiesta `POST` con header `Authorization`.
- Validazione della firma del server tramite la sua chiave pubblica.
- Configurazione tramite variabili d'ambiente, senza dati sensibili nel codice.
- Unit test auto-contenuti, senza chiavi reali e senza chiamate di rete.
- Immagine Docker leggera, con utente non privilegiato e chiavi montate a runtime.
- Pipeline GitHub Actions per eseguire i test a ogni push.

---

## Come funziona HTTP Signature

```
Client                                              Server
  |                                                    |
  | 1. body JSON compatto                              |
  | 2. Digest = "SHA-256=" + Base64(SHA256(body))      |
  | 3. firma RSA dell'header Digest                    |
  |                                                    |
  |-- POST + Digest + Authorization ------------------>|
  |                                                    | 4. ricalcola il digest
  |                                                    | 5. verifica la firma del client
  |                                                    |
  |<-- risposta + Digest + Signature ------------------|
  |                                                    |
  | 6. verifica la firma del server                    |
```

In dettaglio:

1. Il payload viene serializzato in JSON compatto (`separators=(',', ':')`),
   così il digest è riproducibile lato server.
2. Si calcola `SHA-256` del body e lo si codifica in Base64. L'header diventa
   `Digest: SHA-256=<base64>`.
3. L'header `Digest` viene firmato con la chiave privata del client usando
   `rsa-sha256` e padding `PKCS1v15`. La firma Base64 finisce nell'header
   `Authorization`:
   `Signature keyId="client1",algorithm="rsa-sha256",signature="...",headers="digest"`.
4. Il server ricalcola il digest del body e verifica la firma ricevuta.
5. Nella risposta il server allega a sua volta `Digest` e `Signature`.
6. Il client valida la firma del server con `server_public_key.pem`: se la
   verifica fallisce, la risposta potrebbe essere stata manomessa.

---

## Architettura e codice a oggetti

Il codice è diviso per responsabilità:

```
.
├── digest.py             # orchestrazione del flusso HTTP
├── digit_signature.py    # classi OOP per firma e validazione
├── unit_Test.py          # unit test
├── Dockerfile            # immagine del client
├── requirements.txt      # dipendenze Python
├── .gitignore            # esclude chiavi, cache e configurazioni locali
├── .dockerignore         # evita di inserire chiavi nell'immagine
└── README.md
```

### `digit_signature.py`

Contiene le due classi del progetto:

- **`DigitalSignature`**
  - `leggiChiavePrivata()`: carica il file PEM e restituisce un oggetto chiave RSA.
  - `generaFirma(testoFirmato)`: firma il testo con RSA + SHA-256 e padding
    PKCS#1 v1.5, restituendo la firma in Base64.
- **`SignatureValidate`**
  - `leggiChiavePubblica()`: carica la chiave pubblica PEM del server.
  - `verificaChiavePubblica(testoFirmato, firma_base64)`: verifica
    matematicamente la firma e restituisce `True`/`False`, gestendo
    l'eccezione `InvalidSignature`.

Le classi isolano la crittografia dal resto dell'applicazione: chi le usa non
deve conoscere i dettagli di `cryptography`, ma solo il contratto dei metodi.

### `digest.py`

È il livello di orchestrazione. Le operazioni pure sono state estratte in
funzioni testabili:

- `build_body()`: serializza il payload in JSON compatto.
- `build_digest_header()`: calcola l'header `Digest`.
- `build_authorization_header()`: costruisce l'header `Authorization`.
- `extract_signature()`: isola la firma dall'header `Signature` del server.
- `verify_server_signature()`: valida la risposta del server.
- `main()`: legge la configurazione, esegue la `POST` e stampa il dump.

Questa separazione permette di importare il modulo nei test senza eseguire
chiamate di rete: la richiesta HTTP parte solo dentro `main()`.

### `unit_Test.py`

I test verificano:

- correttezza del JSON compatto e del digest SHA-256/Base64;
- formato dell'header `Authorization`;
- estrazione della firma dall'header del server;
- round-trip firma/verifica con una coppia RSA generata al volo;
- rifiuto di un digest manomesso.

Le chiavi usate dai test sono temporanee e vengono eliminate al termine: non
servono chiavi reali e il repository resta pulito.

---

## Requisiti

- Python 3.11+
- Docker (opzionale, per l'esecuzione in container)
- `openssl` (solo se si vogliono generare chiavi di test locali)

Dipendenze Python:

- `requests`
- `cryptography`

---

## Configurazione

Il client non contiene URL, codici o chiavi reali. Tutto viene passato tramite
variabili d'ambiente:

| Variabile | Default | Descrizione |
|---|---|---|
| `SIGNATURE_URL` | `https://example.com/api` | Endpoint del servizio (placeholder) |
| `AUTHOR_NAME` | `Your Name` | Nome autore inviato nel payload |
| `ATTEMPT_CODE` | `YOUR_CODE_HERE` | Codice del tentativo (placeholder) |
| `KEY_ID` | `client1` | Valore `keyId` nell'header `Authorization` |
| `CLIENT_PRIVATE_KEY` | `client_private_key.pem` | Percorso della chiave privata del client |
| `SERVER_PUBLIC_KEY` | `server_public_key.pem` | Percorso della chiave pubblica del server |

> I valori reali di `SIGNATURE_URL` e `ATTEMPT_CODE` non sono versionati.
> Vanno impostati solo nella propria macchina o passati al container.

---

## Avvio locale

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Impostare le variabili d'ambiente e avviare il client:

```bash
export SIGNATURE_URL="https://example.com/api"
export AUTHOR_NAME="Your Name"
export ATTEMPT_CODE="YOUR_CODE_HERE"

python digest.py
```

In alternativa, si possono passare le variabili solo al comando:

```bash
SIGNATURE_URL="https://example.com/api" \
ATTEMPT_CODE="YOUR_CODE_HERE" \
python digest.py
```

---

## Chiavi

Le chiavi **non** devono mai essere committate. Il file `.gitignore` esclude
tutti i file `*.pem`, quindi il repository non può contenere accidentalmente
una chiave privata.

Per generare una coppia di chiavi RSA di test in locale:

```bash
openssl genrsa -out client_private_key.pem 2048
openssl rsa -in client_private_key.pem -pubout -out client_public_key.pem
```

La chiave pubblica del server (`server_public_key.pem`) va fornita dal servizio
con cui si vuole comunicare. Le chiavi pubbliche non sono segreti, ma in questo
progetto anche i file `.pem` pubblici sono ignorati: è una scelta conservativa
per evitare qualsiasi rischio di pubblicare per errore una chiave privata.

Per una verifica rapida che una chiave sia ignorata da Git:

```bash
git check-ignore -v client_private_key.pem
```

---

## Docker

L'immagine **non contiene chiavi**: i file PEM vengono montati in sola lettura
al momento dell'esecuzione.

Build:

```bash
docker build -t http-signature-client .
```

Run (assicurarsi che i due file PEM esistano nella directory corrente):

```bash
docker run --rm \
  -v "$PWD/client_private_key.pem:/app/client_private_key.pem:ro" \
  -v "$PWD/server_public_key.pem:/app/server_public_key.pem:ro" \
  -e SIGNATURE_URL="https://example.com/api" \
  -e AUTHOR_NAME="Your Name" \
  -e ATTEMPT_CODE="YOUR_CODE_HERE" \
  http-signature-client
```

Il container gira con un utente non privilegiato (`appuser`, UID 10001) e non
include test, cache Python o chiavi nell'immagine.

---

## Unit test

Eseguire tutti i test:

```bash
python -m unittest -v unit_Test.py
```

I test non richiedono chiavi reali, non effettuano chiamate HTTP e possono
girare anche in CI. La pipeline in `.github/workflows/tests.yml` li esegue
automaticamente su Python 3.11 e 3.12 a ogni push o pull request.

---

## Sicurezza: scelte adottate

- **Nessuna chiave privata nel repository**: `*.pem` è in `.gitignore` e la
  cronologia Git parte da un repository pulito.
- **Nessun dato sensibile nel codice**: URL e attempt-code sono placeholder;
  i valori reali arrivano da variabili d'ambiente.
- **Nessuna chiave nell'immagine Docker**: `.dockerignore` esclude i PEM e il
  container li riceve solo tramite mount read-only.
- **Container non-root**: riduce la superficie di attacco in caso di compromissione.
- **Timeout HTTP**: la richiesta non può bloccare il client all'infinito.
- **Test isolati**: chiavi RSA temporanee generate a runtime.

---

## Output atteso

Il client stampa il dump completo della risposta:

```text
==DUMP SERVER==
Status HTTP: 200
Header:
content-type: application/json
...

Body:
{...}

 NICE TO HAVE: Validazione della Firma del Server
SUCCESSO: La firma del server è valida. Il mittente è certificato!
```

---

## Autore

**Anis Ravera**
