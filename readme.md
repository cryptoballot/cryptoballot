VoteFlow
-------

VoteFlow is comprised of the following independant components: 

Identity Server
===============
  - Primarily composed of a voter database and a mechanism for voters to supply public key(s).
  - A voter may supply any number of public keys (one key per vote for maximum anonymity)
  - When vote is over and the results finalized, stored public keys can be purged (so all old votes become irreversably anonymized).
  - Any client may check any public-key to verify it is allowed to vote (and what the vote-weight is if being used).
  - Risks include:
     - Account highjacking. This can be mitigated by user-management best practices including 2 factor authentication and email-notifications.
     - Account stuffing (server is hacked and additional user-accounts and PKs are inserted into the database). This can be mitigated by repeatenly verfying the voter-database and monitoring for abnormal public-key registration activity.

Git Server
==========
  - Plain old git server.
  - Each "proposal" is merely a git repository that users may collaboratively edit (through pull requests, forking and the usual means).
  - Public keys may or may not match those stored in Identity server. Users may choose to seperate these concerns for additional security and anonymity.
  - Updating git is entirely independant from voting (although they may optionally be tied together by end-client UI software).
  - Client software may want to have an alert be sent to the user to "update their vote" if their vote no longer points to the "tip" of the repository.
  - Using git ensures that the text-content of proposals are tamper resistant.
  - Risks include:
     - If push access to a respotiroy is comprimised, clumsy client software may acidentally encourage users to update their vote to point to the "tip" of the repository, even though that tip content may be significantly different in intent that what they originally voted for. This is low risk since such tampering is likely to be quickly discovered and rectified.

Voting Server
=============
 - Recives votes signed with pulic key and checks the validity of the vote against the identity server.
 - All votes are identified using a Public Key - no furthur identifying information is provided. 
 - All votes are an ordered list of git urls and commits (/path/to/repo:commit-hash)
 - Any client may request to see their "vote on file", provided such a request is signed with their key.
 - Existing votes may be updated at any time (before counting / tallying takes place).
 - All votes are "sealed" until the votes are ready to be counted. Some clients may choose to make their vote "public".
 - When votes are ready to be counted all votes are "unsealed" in their entirety and published. Any 3rd party may then count the votes and tally the results.
 - Risks include:
    - Voter identity discovery through data-mining / analysis of unsealed votes.

User-interface / client software
--------------------------------
 - Multiple versions may be built by 3rd parties and others.
 - May be server based or a local binary application.
 - Reference implementation here will be an ember.js app.

