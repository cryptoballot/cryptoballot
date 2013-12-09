CryptoBallot
============

WARNING: WORK IN PROGRESS!

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
     - Account highjacking. This can be mitigated by user-management best practices including 2 factor authentication and email-notifications.
     - Account stuffing (server is hacked and additional user-accounts and PKs are inserted into the database). This can be mitigated by repeatenly verfying the voter-database and monitoring for abnormal public-key registration activity.




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

<unsigned-ballot> (Could be blinded or unblinded)

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

`<unsigned-ballot>` is the ballot to be signed. It is encoded as a base64 binary blob and contains no line breaks. Generally it is blinded, but if a voter does not desire anonimity, they may choose just to base64 encode an unblinded ballot. See below under "BallotBox Server" for the ballot specification.

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
    - Voter identity discovery via ip address if either ballot-box server or ssl/tls comprimise. A tor hidden service should be provided in order to mitigate this attack.
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



Git Server (Initiative / ballot creation)
----------------------------
  - Plain old git server.
  - Each "proposal" is merely a git repository that users may collaboratively edit (through pull requests, forking and the usual means).
  - Public keys may or may not match those stored in Identity server. Users may choose to seperate these concerns for additional security and anonymity.
  - Updating git is entirely independant from voting (although they may optionally be tied together by end-client UI software).
  - Client software may want to have an alert be sent to the user to "update their vote" if their vote no longer points to the "tip" of the repository.
  - Using git ensures that the text-content of proposals are tamper resistant.
  - Risks include:
     - If push access to a respotiroy is comprimised, clumsy client software may acidentally encourage users to update their vote to point to the "tip" of the repository, even though that tip content may be significantly different in intent that what they originally voted for. This is low risk since such tampering is likely to be quickly discovered and rectified.



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
