CryptoBallot
============

[![Build Status](https://api.travis-ci.org/cryptoballot/cryptoballot.svg)](https://travis-ci.org/cryptoballot/cryptoballot)
[![Scrutinizer](https://scrutinizer-ci.com/g/cryptoballot/cryptoballot/badges/build.png?b=master)](https://scrutinizer-ci.com/g/cryptoballot/cryptoballot/build-status/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/cryptoballot/cryptoballot)](https://goreportcard.com/report/github.com/cryptoballot/cryptoballot)
[![Coverage Status](https://coveralls.io/repos/github/cryptoballot/cryptoballot/badge.svg?branch=master)](https://coveralls.io/github/cryptoballot/cryptoballot?branch=master)
[![GoDoc](https://godoc.org/github.com/cryptoballot/cryptoballot?status.svg)](https://godoc.org/github.com/cryptoballot/cryptoballot/cryptoballot)
[![Scrutinizer Issues](https://img.shields.io/badge/Scrutinizer-Issues-blue.svg)](https://scrutinizer-ci.com/g/cryptoballot/cryptoballot/issues)

Features
--------
 - All votes are anoymous with an option for the voter to mark their ballot as public.
 - All voters can verify that their vote has been counted
 - All voters can verify that all the votes have been tallied correctly
 - All voters can verify that the total number of signed ballots matches the number of votes cast.
 - Auditors with access to the Voters List can verify the identities of all voters who cast a ballot, but cannot match which ballot belongs to which voter. 



VoterList Server (Voter registry)
---------------------------------
  - Primarily composed of a voter database and a mechanism for voters to supply public key(s).
  - Access to the VoterList should be limited to a verified list of Auditors who can verify the integrity of the VoterList database. Optionally the entire VoterList could be made public if so desired.
  - VoterList should allow anyone to verify that a public-key is active and valid, but should not disclose the identity of the voter with that public key.
  - Risks include:
     - Account stuffing (server is hacked and additional user-accounts are inserted into the database). This can be mitigated by tying voter-database to another trusted ID database. For example, a driver's licence database. This risk is equally present in a paper-based voting system. 



BallotClerk Server (Ballot signing)
----------------------------
  - Each client, before submitting their ballot to the BallotBox must first have it signed by the BallotClerk.
  - The ballot may be blinded before it is submitted, guaranteeing that the ballot is fully anonymous once it is cast
  - Each client will create and sign a Signature Request with their public-key on file with the VoterList.
  - The BallotClerk will verify the request and provide the voter with a signed ballot. The user will then unblind this ballot and submit it to the BallotBox.
  - The BallotClerk publishes the full list of Signature Requests once an election is ended. This allows voters to verify that the total number of signed ballots matches the number of ballots tallied by the BalltoBox.


POSTing a Signature Request takes the following form:
```http
POST /sign/<election-id> HTTP/1.1

<election-id>

<request-id>

<voter-public-key>

<unsigned-ballot-hash> (Could be blinded or unblinded)

<voter-signature>
```

The server will respond with a Fufilled Signature Request, which takes the following form:

```
<signature-request>

<ballot-signature>
```

`<election-id>` is the unique identifier for this election / decision.

`<request-id>` is the unique identifier for this Signature Request. It is the (hex encoded) SHA-512 of the voter-public-key.

`<voter-public-key>` is the voter's rsa public key for this vote. It is base64 encoded and contains no line breaks.

`<unsigned-ballot-hash>` is the SHA512 hash of the ballot to be signed. It is encoded in hex. Generally it is blinded, but if a voter does not desire anonimity, they may choose just to use the raw hex-encoded SHA512 of an unblinded ballot. See below under "BallotBox Server" for the ballot specification.

`<voter-signature>` is the base64 encoded signature of the entire body up to this point (excluding headers and the linebreak immidiately preceding the signature). 


The BallotClerk Server also exposes the following service points

`GET /sigs/<election-id>` provides the full list of all Fufilled Signature Requests for the election. This service point is only available to the public after the election is over.

`GET /sigs/<election-id>/<request-id>` provides access to a single Fufilled Signature Request. A user may use this to regain a lost ballot-signature. They will have to attach a X-CryptoBallot-Signature header which signs the string `GET /sigs/<election-id>/<request-id>` with their public key. 



BallotBox Server
----------------
 - Recives votes signed with BallotClerk key and checks the validity of the submitted ballot.
 - All ballots are identified using a randomly user generated ID and not two ballots may share this ID. This is to prevent signed ballot copying / stuffing. 
 - All votes are an ordered list of git urls and commits (/path/to/repo:commit-hash)
 - Any client may request to see their "ballot on file". 
 - Existing ballot may be updated at any time (before counting / tallying takes place). This is accomplished by getting a new ballot signed that includes an revokation of the previous ballot.
 - All ballots are "sealed" until the votes are ready to be counted. Some clients may choose to make their vote "public" by tagging it as such. 
 - When ballots are ready to be counted all votes are "unsealed" in their entirety and published. Any 3rd party may then count the votes and tally the results.
 - Risks include:
    - Voter identity discovery via ip address if either ballot-box server or ssl/tls compromise. A tor hidden service should be provided in order to mitigate this attack.
    - Voter identity discovery though a timing attack if the user immidiately submits their ballot after having it signed by the Ballot Clerk. To mitigate this attack the voter should randomly stagger this interval.


Casting a ballot takes an HTTP request of the following form

```http
PUT /vote/<election-id>/<ballot-id> HTTP/1.1

<election-id>

<ballot-id>

<vote>

<tags>

<ballot-signature>
```

`<election-id>` is the unique identifier for this election / decision.

`<ballot-id>` is the unqiue ID of this ballot. It is the (hex-encoded) SHA512 hash of randomly generated bits. This is to prevent signed ballot copying / stuffing. If two ballots are discovered with the same ballot-id, they are invalid.

`<vote>` is an ordered, line-seperated list of git addresses and commit hashes that represent the vote

`<tags>` is additional information a voter may wish to attach to the vote in the format of `key="value"`. Each key-value pair goes on a new line. Standardization around commonly understood keys forthcoming. Examples might include the voter's name if they wish to publically forclose their vote.

`<ballot-signature>` is the base64 encoded BallotClerk signature of the ballot. This is the entire body up to this point (excluding headers and the linebreak immidiately preceding the signature). This signature is provided by the BallotClerk Server in a Fufilled Signature Request.



User-interface / client software
--------------------------------
 - Multiple versions may be built by 3rd parties and others.
 - May be server based or a local binary application.
 - Reference implementation here will be an ember.js app.



Verifying an election
---------------------
The following steps can be taken to do an end-to-end verification of an election
 1. Retrieve the full ballot box for an election from the Ballot Box server and verify the SHA512 signature of the result set with other clients.
 2. Retrieve the BallotClerk's public key and verify that all ballots have been properly signed by the BallotClerk.
 3. Verify that no two ballots share the same ID.
 4. Tally the ballots and verify that other clients have tallied the same result.
 5. Retrieve the full set of Fufilled Signature Requests from the Ballot Clerk and verify the SHA512 signature of the set with other clients.
 6. Verify the the number of ballots is not more than the number of Fufilled Signature Requests.
 7. Verify the voter signature on all Signature Requests against the voters' public keys.
 8. Contact the VoterList server and verify that all public keys belong to verified voters.



Shortcomings
------------
1. Cryptoballot provides no guarantees of endpoint security of the machine or software being used to cast the vote. 
2. Cryptoballot does not provide any protection against voter coersion. Since cryptoballot allows voters to view their vote after it has been counted in order to verify the veracity of the election, this opens the door to private coersion of votes or vote-trading. This problem is not unique to Cryptoballot and is endemic to any electronic voting system that allows voting on private devices in a private setting.



Generating Crypto Keys
----------------------
```bash
#Generate private-key. This is your private key. Keep it secret, keep it safe.
openssl genrsa -out private.key 1024

#Generate public-key der file
openssl rsa -in private.key -out public.der -outform DER -pubout

#Gerenate base64 encoded public key - this is the <public-key> you will pass to the BallotClerk server for ballot signing
base64 public.der -w0 > public.der.base64

#Generate SHA512 request-id from public key. This is your <request-id> for creating a Signature Request
sha512sum public.der.base64 | awk '{printf $1}' > public.der.base64.sha512
```

Paper Voting Equivalent to CryptoBallot
---------------------------------------

|Paper Voting Equivalent                                              | CryptoBallot
|---------------------------------------------------------------------|-----------------------------------------------------------------------------
|                                                                     | User generates private / public RSA keypair
|Voters registers to vote and is put on voters list                   | User registers to vote and is put on voters list along with their public key
|*Election Time!*                                                     | *Election Time!*
|Voter receives blank ballot by mail with unique ID stamped in corner | Voter randomly generates unique ID for ballot
|Voter writes down vote on their ballot at home                       | Voter creates digital ballot file on personal device using the generated ID
|Voter puts ballot in an envelope along with carbon paper             | Voter creates a blinded copy of their ballot using RSA blinding
|Voter presents ID to voting-station clerk who verifies identity      | Voter asserts identity to Ballot-Clerk server using crypto-signature
|Voting-station clerk has voter sign receipt. Clerk keeps receipt.    | Ballot-Clerk server stores copy of the voter's signature-request as a receipt
|Voting-station clerk signs outside of envelope                       | Ballot-Clerk server blind-signs voter's blinded-ballot
|Voter removes ballot from envelope and discards carbon paper         | Voter unblinds digital ballot
|Voter goes to private voting booth                                   | Voter waits a random amount of time and enables Tor
|Voter places ballot in ballot-box                                    | Voter submits ballot to Ballot-Box server (which checks ballot-clerk signature on ballot)
|*Counting time!*                                                     | *Counting time!*
|Clerk's signature is published                                       | Ballot-Clerk's public-key is published
|All ballots are poured out on big counting table                     | All ballots are published in the open
|All ballots are checked for the clerk's carbon-copied signature      | All ballots are cryptographically verified against Ballot-Clerk server's public key / signature
|All ballots are checked to make sure they have a unique-id           | All ballots are checked to make sure they have a unique-id
|Count the ballot and the receipts, make sure receipts >= ballots     | Count the ballot and the signature-request receipts, make sure receipts >= ballots
|Auditors verify receipts are properly signed by a registered voter   | Auditors verify signature-request receipts are properly signed by a registered voter
|Tally the results of the election!                                   | Tally the results of the election!

Database Setup
--------------
The system can build the database schema automatically. Run either of the following:

    ballotbox --set-up-db
    electionclerk --set-up-db
