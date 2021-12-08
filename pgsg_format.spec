The notarization document which PageSigner produces (*.pgsg) is a JSON file with base64-encoded field values.  

The overview of most of the fields is given here: https://tlsnotary.org/how_it_works#section6
This documents provides a more in-depth description of each field.
All integers are stored in big-endian format. 


The following 8 elements are concatenated and then signed by the Notary.

--- 1. Client's hash commitment to the server response (32 bytes).

This is a 32-byte sha256 hash over a concatenation of all TLS records of the server response with the 16-byte MAC at the end of each record. The 8-byte explicit nonce at the beginning of each TLS record is not included. All records are concatenated sequentially according to the TLS record sequence number and then hashed.


--- 2. Client's hash commitment to the Client's shares of the TLS session keys (32 bytes).

This is a 32-byte sha256 hash over the concatenation of the Client's xor shares of:
  16-byte client_write_key
+ 4-byte client_write_iv
+ 16-byte server_write_key
+ 4-byte server_write_iv


--- 3. Client's hash commitment to the Client's share of the PMS (32 bytes).

This is a 32-byte sha256 hash over the Client's additive share of the pre-master secret. The share is 0-padded with leading bytes to a 32-byte length and then hashed.


--- 4. GHASH inputs used when computing MAC for the request (variable length).

This is a concatenation of:
A + A padding + C + C padding + suffix, where

A is additional authenticated data and is a concatenation of:
  8-byte TLS record sequence number
+ 0x23 0x03 0x03 (magic bytes for TLS 1.2)
+ 2-byte TLS record's bytelength

"A padding" is padding of 0 bytes on the right of A to bring the bytelength of A to 16.

C is client request's ciphertext without the MAC and without the explicit nonce. Currently, the client is allowed to send only 1 TLS record, hence C consists of only one TLS record.

"C padding" is padding of 0 bytes on the right of C to bring the bytelength C to the nearest multiple of 16.

suffix is a concatenation of:
  8-byte _BIT_length of A (it is always 13*8=104)
+ 8-byte _BIT_length of C (before padding)


--- 5. Webserver's ephemeral pubkey used when computing shares of PMS (65 bytes).

This is an EC P256 pubkey which the webserver sends in the Server Key Exchange message during the TLS handshake. It is a concatenation of:
  0x04 (means compressed keys)
+ 32-byte x coordinate
+ 32-byte y coordinate


--- 6. Notary's PMS share (32 bytes).

This is a 32-byte Notary's additive share of the pre-master secret. The share is 0-padded with leading bytes to a 32-byte length.


--- 7. Notary's TLS session keys (40 bytes).

A concatenation of the Notary's xor shares of:
  16-byte client_write_key
+ 4-byte client_write_iv
+ 16-byte server_write_key
+ 4-byte server_write_iv


--- 8. Notarization timestamp (8-bytes).

A number of seconds since Unix epoch.


In addition to the elements signed by the Notary, the Client also includes in the notarization document the following:


--- 9. Notary's signature over the above 8 elements (64 bytes).

The above 8 elements are concatenated, then hashed with sha256 and the hasn is signed with ECDSA P256. 
The signature is a concatenation of:
  32-byte r value
+ 32-byte s value


--- 10. x509 certificate chain from the webserver's "Certificate" TLS message (variable length).

A JSON object with the key serving as index i.e {"0": cert0, "1": cert1, ...}, where cert1, cert2 ... are base64-encoded DER-formatted certificates.
The leaf certificate has index "0". The root certificate will have the highest index.
It is allowed for the webserver to not send the intermediate certificates in the "Certificate" TLS message but to instead embed into the leaf certificate the URL from which to fetch the intermediate certificate. In such case, the intermediate certificate will already have been fetched and will appear here.


--- 11. client_random and server_random values of the TLS session (64 bytes).

This is the 32-byte client_random value from Client Hello and the 32-byte server_random value from Server Hello.


--- 12. Webserver's signature over ephemeral pubkey and random values from the "Server Key Exchange" TLS message (The length depends on the webserver's RSA pubkey size). 

The only currently supported signature algorithm is rsa_pkcs1_sha256. 
The bytes that are signed are:
  client_random
+ server_random
+ 0x03 0x00 0x16 0x41 (means curve P256 with 65-byte pubkey)
+ 65-byte ephemeral pubkey from Step 5.


--- 13. Client's TLS session keys (40 bytes).

A concatenation of the Client's xor shares of:
  16-byte client_write_key
+ 4-byte client_write_iv
+ 16-byte server_write_key
+ 4-byte server_write_iv


--- 14. Client's share of the PMS (32 bytes).

This is a 32-byte Client's additive share of the pre-master secret. The share is 0-padded with leading bytes to a 32-byte length.


--- 15. Webserver response with MAC (variable length).

A concatenation of all TLS records according to the TLS record sequence number. The 16-byte MAC at the end of each record is included. The explicit nonce is not included.