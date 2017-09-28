Ballot Clerk
============

This is a ballot clerk server. It is responsible for signing ballots as part of the CryptoBallot protocol.

It currently supports the following service points:

`GET /`

The root index displays the readme. You're looking at it.

`POST /sign`

This allows the voter to POST their ballot to the ballot clerk in order to get it signed. The POST must come in the form of a Signature Request. The server will respond with a Fulfilled Signature Request.

`GET /publickey`

This displays the public key, used by the ballot clerk for signing ballots. 
