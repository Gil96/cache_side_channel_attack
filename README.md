# cache_side_channel_attack
Cache side channel attack project on OpenSSL AES implementation


Attack Features: (might change over time)
- ECB MODE
- T-BOX (256* 4Bytes)
- L1-DATA cache
- Plaintext known & inputted
- Table Addresses known (at least one)
  - Table offsets known (at least one)
  
  
 
Attack Procedure:
```
(required the instalation of the package pyfinite)
> cd /program
> make
> ./atk
> python3 crypto.py
```
