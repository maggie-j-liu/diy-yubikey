## Key setup

There have already been keys generated and placed in `keys.h` to make the code run, but you should regenerate and add your own keys.

To generate the master key, run

```sh
openssl rand -hex 32
```

Then, reformat the output as an array and add it to `keys.h` as the `MASTER_KEY`.


For the attestation key and certificate, first generate a private key with

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ecprivkey.pem
```

Then print out the attestation key with

```sh
openssl ec -in ecprivkey.pem -text -noout
```

Take the indented bytes under `priv:`, format them, and add to `keys.h` as the `ATTESTATION_KEY`. If the first byte is `00`, remove it. The total length should be 32 bytes.

Generate a certificate with

```sh
openssl req -new -x509 -key ecprivkey.pem -out certificate.pem -days 3650
```

You don't have to fill out every field; I just filled out the Common Name.

Then print out the attestation certificate with 

```sh
openssl x509 -in certificate.pem -noout -C
```

and copy the bytes in `XXX_certificate` to `keys.h` as the `ATTESTATION_CERT`.
