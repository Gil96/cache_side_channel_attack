# cache_side_channel_attack
Cache side channel attack project on OpenSSL AES implementation


Attack Features: (might change over time)
- ECB MODE
- T-BOX (256* 4Bytes)
- L1-DATA cache
- Plaintext known & inputted
- Table Addresses unknown
- Table Offsets unknown
  
  
 

Attack Procedure:
```
(required the instalation of the package pyfinite)
> cd /program
> make
> ./atk
> python3 crypto.py
```


Project Structure:
```
/usr - contains OPENSSL 0.9.
/program - contains the measurement_program, victim, crypto_analysis_program, measurement data
/others  - contains related information about this project
```
