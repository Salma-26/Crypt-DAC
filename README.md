````# Crypt-DAC: Cryptographically Enforced Dynamic Access Control

A Java/JSP/Servlet/MySQL web app for an untrusted cloud (honest-but-curious). Revoking access
adds an encryption layer in the cloud, so the owner never re-uploads the file.

## Techniques implemented
| Technique | Where |
|---|---|
| Delegation-aware key list (compact, wrapped per user with RSA-OAEP) | `FileService.rewrapAll`, `CryptoUtil.wrap` |
| Adjustable onion encryption (cloud adds an AES-GCM layer per revocation, bound `MAX_LAYERS = 5`) | `FileService.addLayer`, `revokePolicy` |
| Delayed de-onion (next write picks a fresh file key and clears layers) | `FileService.write` |
| Integrity verification (SHA-256 over ciphertext chunks) | `FileService.checksum`, Verify button |
| Expiring permissions (auto-revoked when the owner opens the dashboard) | `FileService.sweepExpired` |

## Roles
- **Cloud server**: authorizes owners and users, sees ciphertext only, views transactions, delay and throughput.
- **Data owner**: upload, update, delete, verify, grant (with expiry), revoke.
- **End user**: request access, download and decrypt.

## Requirements
JDK 11+, Maven 3.6+, MySQL 8, Apache Tomcat **9** (javax.servlet; Tomcat 10 needs a jakarta migration).

## Run
```bash
mysql -u root -p < sql/schema.sql
cp src/main/resources/db.properties.example src/main/resources/db.properties   # edit credentials
mvn clean package
cp target/crypt-dac.war $TOMCAT_HOME/webapps/
$TOMCAT_HOME/bin/startup.sh        # Windows: bin\startup.bat
```
Open http://localhost:8080/crypt-dac/ See the full [Project Guide](docs/PROJECT_GUIDE.md).```
## Try it
1. Register an owner (`alice_owner`) and two users (`bob`, `carol`).
2. Sign in as cloud (`cloud.user` / `cloud.password` from db.properties) and **Authorize** all three.
3. Owner: upload a file. Users: **Request access**. Owner: **Approve**.
4. Bob and Carol: **Download and decrypt**.
5. Owner: **Revoke** Bob. Bob's download is now denied; Carol still downloads. The file shows 1 onion layer.
6. Owner: **Update file**. Layers reset to 0.

## Crypto demo without a database
After `mvn compile`: `java -cp target/classes com.cryptdac.util.Demo`

## Security notes (read before real use)
- Private keys are encrypted with a PBKDF2 key derived from the user's password and decrypted at login.
- Change the cloud credentials in `db.properties`; it is git-ignored. Commit only `db.properties.example`.
- Not included: HTTPS (enable it on Tomcat), CSRF tokens, rate limiting, key recovery.
- Only `read` is enforced for end users; `write` is stored as a privilege label.
- The cloud and owner share one server process in this demo; in production the cloud would be a separate service.
