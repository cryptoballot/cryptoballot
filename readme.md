CryptoBallot
===========

WARNING: WORK IN PROGRESS!

Features
--------
 - All votes are anoymous with an option for the voter to mark their ballot as public.
 - All voters can verify that their vote has been counted
 - All voters can verify that all the votes have been tallied correctly
 - All voters can verify that the total number of signed ballots matches the number of votes cast.
 - Auditors with access to the Voters List can verify the identities of all voters who cast a ballot, but cannot match which ballot belongs to which voter. 


CrytoBallot is comprised of the following independant components: 

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

BallotBox Server
----------------
 - Recives votes signed with BallotClerk key and checks the validity of the submitted ballot.
 - All ballots are identified using a randomly user generated ID and not two ballots may share this ID. This is to prevent signed ballot copying / stuffing. 
 - All votes are an ordered list of git urls and commits (/path/to/repo:commit-hash)
 - Any client may request to see their "ballot on file". Since all ballots are keyed by a random string, the ballots are essentially private until revealed.
 - Existing ballot may be updated at any time (before counting / tallying takes place). This is accomplished by getting a new ballot signed that includes an revokation of the previous ballot.
 - All ballots are "sealed" until the votes are ready to be counted. Some clients may choose to make their vote "public" by tagging it as such. 
 - When ballots are ready to be counted all votes are "unsealed" in their entirety and published. Any 3rd party may then count the votes and tally the results.
 - Risks include:
    - Voter identity discovery via ip address if either ballot-box server or ssl/tls comprimise. A tor hidden service should be provided in order to mitigate this attack.


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

API
---

The voting server is a RESTful service (Supporting GET, PUT and DELETE verbs) with a few additions to cryptographically guarantee that the request is coming from a trusted voter.

Casting a ballot takes an HTTP request of the following form
```http
PUT /vote/<election-id>/<ballot-id> HTTP/1.1
X-Voteflow-Public-Key: <public-key>
X-Voteflow-Signature: <request-signature>

<election-id>

<ballot-id>

<public-key>

<vote>

<tags>

<ballot-signature>
```

`<election-id>` is the unique identifier for this election / decision.

`<ballot-id>` is the unqiue ID of this ballot. It is the (hex-encoded) SHA512 hash of this voter's public key for this vote.

`<public-key>` is the voter's rsa public key for this vote. It is base64 encoded and contains no line breaks.

`<request-signature>` is the base64 encoded signature for the request (but not the ballot). Using their RSA private-key and SHA512, the voter signs a string in the following format `<METHOD> /vote/<election-id>/<ballot-id>`, where `<METHOD>` is the HTTP Method / Verb. For example `PUT /vote/12345/183fd27b0e7292b54090519510b99253aa1228f8795003ebd58561...`.

`<vote>` is an ordered, line-seperated list of git addresses and commit hashes that represent the vote

`<tags>` is additional information a voter may wish to attach to the vote in the format of `key="value"`. Each key-value pair goes on a new line. Standardization around commonly understood keys forthcoming. Examples might include the voter's name if they wish to publically forclose their vote.

`<ballot-signature>` is the base64 encoded signature of the entire body up to this point (excluding headers and the linebreak immidiately preceding the signature). 

Generating Crypto Keys
----------------------
```bash
#Generate private-key. This is your private key. Keep it secret, keep it safe.
openssl genrsa -out private.key 1024

#Generate public-key der file
openssl rsa -in private.key -out public.der -outform DER -pubout

#Gerenate base64 encoded public key - this is the <public-key> you will pass to the server
base64 public.der -w0 > public.der.base64

#Generate SHA512 ballot-id from public key. This is your <ballot-id>
sha512sum public.der.base64 | awk '{printf $1}' > public.der.base64.sha512

#Generate request text (the -n switch makes sure we don't pad a newline character, which is echo's default behavior)
echo -n PUT /vote/12345/`cat public.der.base64.sha512` > request.txt

#Sign the request. This is your <request-signature>
openssl sha -sha512 -sign private.key < request.txt | base64 -w0 > request.txt.signed
```
