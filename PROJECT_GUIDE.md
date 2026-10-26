# Crypt-DAC: Project Guide

Cryptographically Enforced Dynamic Access Control for an untrusted cloud.
This guide records what was built, which tools were used, how it works, how it was set up and run, and the results.

---

## 1. Problem and idea

Files stored in a cloud can be leaked if the cloud is not fully trusted. Encryption protects the files, but **removing a user's access** (revocation) is expensive: the owner normally has to download the file, re-encrypt it with a new key, and upload it again.

**Crypt-DAC** removes that cost:

- The owner never re-uploads the file.
- The **cloud adds one more encryption layer** ("onion layer") when a user is revoked.
- The cloud only ever sees ciphertext and a revocation key. It never sees the file key.
- The revoked user's old keys can no longer unlock the file.

This project is an implementation of the Crypt-DAC idea from the research paper cited in the project report.

---

## 2. Technologies used

| Part | Technology | Version used |
|---|---|---|
| Language | Java | 17 (Temurin) |
| Web layer | JSP and Servlets | Servlet 4.0 |
| Web server | Apache Tomcat | 9.0.123 |
| Build tool | Apache Maven | 3.10.0 |
| Database | MySQL | 8.0.46 (port 3307) |
| DB driver | MySQL Connector/J | 8.0.33 |
| Encryption | AES-256-GCM | per chunk and per layer |
| Key wrapping | RSA-2048 with OAEP (SHA-256) | per user |
| Password hashing | PBKDF2-HMAC-SHA256 | 120,000 iterations |
| Version control | Git and GitHub Desktop | |

Tomcat 9 is required because the project uses `javax.servlet`. Tomcat 10 and later use `jakarta.servlet`.

---

## 3. Project structure

```
Crypt-DAC/
├── pom.xml                       Maven build file
├── README.md
├── LICENSE
├── .gitignore                    keeps db.properties out of GitHub
├── sql/schema.sql                database and 7 tables
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROJECT_GUIDE.md          this file
│   └── screenshots/              result images
└── src/main/
    ├── java/com/cryptdac/
    │   ├── util/
    │   │   ├── CryptoUtil.java   AES-GCM, RSA wrap, PBKDF2
    │   │   ├── FileService.java  upload, layers, revoke, verify
    │   │   ├── DB.java           database connection
    │   │   ├── Html.java         output escaping
    │   │   └── Demo.java         crypto walkthrough without a database
    │   └── web/
    │       ├── AuthServlet.java  register, login, logout
    │       ├── OwnerServlet.java upload, update, delete, verify, grant, revoke
    │       ├── UserServlet.java  request access, download and decrypt
    │       └── CloudServlet.java authorize accounts
    ├── resources/db.properties.example
    └── webapp/                   JSP pages and CSS
        ├── index.jsp             sign in and register
        ├── owner.jsp
        ├── user.jsp
        ├── cloud.jsp
        └── css/style.css
```

---

## 4. The three roles

| Role | What they can do |
|---|---|
| **Cloud server** | Authorize new owner and user accounts. Sees only encrypted data. Views transactions, time delay and throughput. |
| **Data owner** | Upload, update, delete and verify files. Grant access with an expiry time. Revoke access. |
| **End user** | See files, request access, download and decrypt files they were granted. |

---

## 5. How it works

### 5.1 Keys

- Every owner and user gets an **RSA key pair** when they register. The public key is stored in the database. The private key is encrypted with a key derived from the account password, so only that password can unlock it.
- Every file gets a random **file key (Kf)**.
- The **key list** is the file key followed by one revocation key per revoke:

```
key list = Kf || Kr1 || Kr2 || ... || Krn     (32 bytes each)
```

### 5.2 Storing a file

1. The file is split into 64 KB chunks.
2. Each chunk is encrypted with AES-256-GCM using Kf.
3. The key list is wrapped for the owner with the owner's RSA public key.
4. A SHA-256 checksum of all ciphertext chunks is stored for later verification.

### 5.3 Granting access

1. A user clicks **Request access**.
2. The owner clicks **Approve**, which sets a privilege and an expiry time.
3. The owner unwraps the key list and wraps it again with the user's public key.
4. The user downloads, unwraps the list with their private key, and decrypts.

### 5.4 Revoking access (the main feature)

```
 Owner                         Cloud                        Revoked user
   |                             |                               |
   | 1. mark policy inactive     |                               |
   | 2. make new key Kr          |                               |
   |---- Kr ------------------->| 3. wrap every chunk with Kr    |
   | 4. append Kr to key list    |    (layer count + 1)           |
   | 5. re-wrap list for the     |                               |
   |    remaining users          |                               |
   |                             |        old list has no Kr -----X can't remove outer layer
```

Decryption order for a file with n layers:

```
ciphertext -> remove layer Krn -> ... -> remove layer Kr1 -> decrypt with Kf -> plaintext
```

A user whose key list has fewer keys than the file has layers cannot decrypt. The code reports "Key list is stale: access has been revoked".

### 5.5 The three techniques from the paper

| Technique | In this project |
|---|---|
| Delegation-aware encryption | The cloud updates the encrypted file during revocation, and the key list is kept compact and re-wrapped per user. |
| Adjustable onion encryption | Each revoke adds one layer. The layer limit is 5 (`MAX_LAYERS`). The owner page warns when it is reached. |
| Delayed de-onion encryption | The next **Update file** uses a fresh file key and clears all layers (layers back to 0). |

### 5.6 Extra features

- **Verify:** recomputes the checksum and detects tampering by the cloud.
- **Expiring permissions:** an expired policy is revoked automatically when the owner opens the owner page.
- **Audit log:** each action stores its time, size and delay. The cloud page shows delay and throughput.
- **Account approval:** new accounts stay `pending` until the cloud server authorizes them.

### 5.7 Database tables

| Table | Purpose |
|---|---|
| `data_owners` | owner accounts, public key, encrypted private key, status |
| `end_users` | user accounts, public key, encrypted private key, status |
| `files` | file name, owner-wrapped key list, layer count, checksum |
| `file_chunks` | encrypted chunks |
| `access_policies` | who can read which file, expiry, user-wrapped key list |
| `access_requests` | pending and approved requests |
| `audit_logs` | actions with time, bytes and delay |

---

## 6. Setup procedure (what was done, in order)

### Step 1: Install and check the tools (Windows)

| Tool | Check command | Result |
|---|---|---|
| Java 17 | `java -version` | Temurin 17.0.20 |
| Maven | `mvn -version` | Apache Maven 3.10.0 on Java 17 |
| MySQL 8 | `SELECT version();` in the MySQL client | 8.0.46 |
| Tomcat 9 | run `startup.bat`, read the log | "Server startup in ... milliseconds" |

Setup notes:

- Java 8 was installed first, so Java 17 was installed and `JAVA_HOME` was set to the Temurin 17 folder.
- Maven was extracted to `C:\Tools\apache-maven-3.10.0` and its `bin` folder was added to PATH.
- Tomcat 9 was extracted to a `CTools` folder.

### Step 2: Create the database

```
mysql> source C:/Users/<you>/Desktop/Crypt-DAC/Crypt-DAC/sql/schema.sql
mysql> USE cedac;
mysql> DESCRIBE data_owners;
```

An older `cedac` database with fewer columns was dropped first (`DROP DATABASE cedac;`) and the script was run again.

### Step 3: Set the database details

File `src/main/resources/db.properties` (not uploaded to GitHub):

```
url=jdbc:mysql://127.0.0.1:3307/cedac?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
user=root
password=<your MySQL password>
cloud.user=cloudadmin
cloud.password=<at least 6 characters>
```

### Step 4: Build

```
cd Crypt-DAC\Crypt-DAC
mvn clean package
```

Result: `BUILD SUCCESS`, which produces `target/crypt-dac.war`.

### Step 5: Deploy and start

1. Copy `crypt-dac.war` into `apache-tomcat-9.0.123\webapps`.
2. Run `bin\startup.bat` and leave the window open.
3. Open `http://localhost:<port>/crypt-dac/` in the browser's address bar.

---

## 7. Problems met and how they were fixed

| Problem | Cause | Fix |
|---|---|---|
| `java -version` showed 1.8 | old Java first in PATH | installed Java 17, set `JAVA_HOME` |
| `mvn` said JAVA_HOME not defined | variable missing | set `JAVA_HOME` to the JDK folder |
| Old MySQL 5.1 answered the app | two MySQL servers installed | stopped the old one, used MySQL 8 on port 3307 |
| Error `CLIENT_PLUGIN_AUTH is required` | app connected to MySQL 5.1 on port 3306 | pointed the URL to port 3307 |
| Browser asked for a username and password | another program (Oracle) used port 8080 | moved Tomcat to another port in `conf/server.xml` |
| `Communications link failure` | the deployed settings file still had the old port | edited `webapps/crypt-dac/WEB-INF/classes/db` (the real file), then restarted Tomcat |
| "Enter a name and a password of at least 6 characters" | cloud password was 5 characters | used a password of 6 or more characters |
| "Wrong name or password" | wrong role in the dropdown, or a different account name | selected the correct role and typed the exact name |

---

## 8. How to use the application

1. **Register** an owner and one or more users. Choose the right role in the dropdown.
2. Sign in as **Cloud server** (`cloud.user` and `cloud.password`) and click **Authorize** for each account.
3. Sign in as the **owner** and upload a file.
4. Sign in as a **user** and click **Request access**.
5. Sign in as the **owner** and click **Approve**.
6. Sign in as the **user** and click **Download and decrypt**. The file opens with the original text.
7. Sign in as the **owner** and click **Revoke** next to a user.
8. The revoked user now sees **No access**. The other users still download the file.

---

## 9. Results

Observed during testing:

| Test | Result |
|---|---|
| Project build | BUILD SUCCESS |
| Database | 7 tables created, columns correct |
| Register and authorize | owner and users created, status changed to authorized |
| Upload | file encrypted, shown with "onion layers 0/5" |
| Request and approve | owner page listed the request, access granted |
| Download | user downloaded and decrypted the file |
| Revoke one of two users | message "Access revoked immediately (new onion layer added)" |
| After revoke | file shows "onion layers 1/5", only the remaining user stays in the access table |
| Remaining user | still sees **Granted** and can download the file after the new layer was added |

Screenshots are in `docs/screenshots/`.

Key outcome: access was removed immediately, with no re-upload by the owner, and the remaining users kept working access.

---

## 10. Limitations and security notes

- The cloud and owner logic run in one server process in this demo. In production the cloud would be a separate service.
- Only the `read` privilege is enforced. `write` is stored as a label.
- There is no HTTPS, CSRF protection or rate limiting. Enable HTTPS on Tomcat before real use.
- Passwords cannot be recovered, because the private key is locked with the password.
- A user who copied the plaintext before revocation still has it. Cryptography cannot take back data already read.
- `db.properties` holds passwords and must never be uploaded to GitHub.

---

## 11. Possible future work

- Separate cloud service with its own database.
- Enforce write privileges.
- Folder-level policies and user groups.
- HTTPS, CSRF tokens and login rate limiting.
- Automatic de-onion when the layer limit is reached.
