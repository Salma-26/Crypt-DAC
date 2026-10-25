# Key list model
Key list = Kf || Kr1 || ... || Krn (32 bytes each). The cloud stores chunks as
AES-GCM(Krn, ... AES-GCM(Kr1, AES-GCM(Kf, chunk))).

- Upload: fresh Kf, key list = [Kf], wrapped for owner and each granted user.
- Revoke: owner generates Kr, cloud wraps every chunk with Kr, owner appends Kr and re-wraps for remaining users.
  A revoked user holds a list without Kr and cannot remove the outer layer.
- Write: fresh Kf, layers reset to 0 (delayed de-onion).
