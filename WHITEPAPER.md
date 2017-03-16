# CryptoBallot Whitepaper - DRAFT - Work In Progress

##Definitions

 - VotersList:  Web application for managing voter information and public keys.

 - VotersList Document: A document that contains all voter information, with the exception of public keys. This document would generally be derived from a polity's voters list. 

 - VotersList Agent: A trusted agent that is reponsible for certifying a voter's identity and their associated public key

 - VotersList Auditor: A semi-trusted agent that can view the VotersList and associated public keys. Used to do a full verification of the CrytoBallot voting protocol. Generally these would be idependent volunteers who would have clearence to view the full voters list. 

 - VotersList Administrator: A semi-trusted agent that is responsible for uploading and certifying the VotersList Document. This agent would generally be the Cheif Electoral Officer responsible for the election. 


##VotersList

The CrytoBallot VotersList is a RESTful web application for managing, distributing, and tamperproofing voter identity information. 

VotersList has the following primary functions: 

1. Allows VotersList Administrators upload a static VotersList Document, which holds all voter identity information, with the exeption of voters' public keys. 

2. Allows VotersList Agents to associate a voter's public key with their record in the VotersList Document. 

3. Allows voters to verify all their information on file, including their registered public key. 

4. Allows VotersList Auditors to verify the VotersList Document and all voters public keys on file. 


#### VotersList threat model

1. An attacker has an arbitrary amount of computing power equivilent to the computer power available to a large nation state. 

2. An attacker has complete control over the computer running the VotersList application and has complete control over VotersList Administrators' computers, but does not have control over VotersList Agent computers, VotersList Auditor computers, or voter's computers. 


#### VotersList security guaruntees

1. An attacker can spoil a VotersList Document, but cannot modify it without VotersList Auditors noticing. Any CryptoBallot election based on a tempered VotersList Document would fail verification.

2. An attacker can spoil a Voter's public key on file, but cannot modify it without without VotersList Auditors or voters noticing. Any CryptoBallot election with tampered public keys would fail verification.


#### VotersList WorkFlow

*Before voting*

1. System administrators upload Administrator, Agent and Autitor public keys to the VotersList server as part of the configuration of the server.
2. The VotersList server is booted and the RESTful service is online. 
3. The Administrator transforms the polity's voters list into a VotersList Document and signs the document with their key. The VotersList Document is PUT to the VotersList server and is identified using the hash of the document. The contents of the VotersList Document is now secure against tampering since it is signed by the semi-trusted Administrator and cannot be modified without it's ID being modified. 
4. The VotersList Agent interacts with voters to verify voter identity. Once the voter's identity has been verified, the Agent signs the voter's pubic key together with their voter ID with the Agent's trusted key. The exact nature of this interaction will vary depending on the polity. Examples include a human verifying identity information in-person, or a web application that voters interface with digitally. Generally the Agent would be expected to keep good records so an audit can be conducted of it's acivities. 
5. The voter PUTs their signed public key and voter ID, registering with the VotersList server. 

*After voting*

1. Administrators, Agents, and Auditors verify with each other that the public keys registered on the VotersList server are correct and accounted for. 
2. Auditors verify that all Fulfilled Signature Request on file with the Election Clerk are properly signed by a voters key and that each voter's key is signed by a valid Agent key. 
3. Auditors perform any additional audit of Agent records as required. 
4. Auditors publically communicate the results of their audit. 


#### The VotersListDocument

The VotersListDocument is a utf8 encoded file in the following format:

```
<voters-list-document-id>


<array-of-voters-information>


<admin-public-key>

<signature>
```

  - `<voters-list-document-id>` is a base64 encoded SHA256 hash of `<array-of-voters-information>`

  - `<admin-public-key>` is a base64 encoded public-key corresponding to a single VotersList Administrator. 

  - `<signature>` is an RSA signature of the document up to this point, excluding the 2-line seperator ('\n\n') before `<signature>`. This signature is signed using private-key associated with `<admin-public-key>`. 

  - `<array-of-voters-information>` is a 2-line seperated (`\n\n`) concactenation of VoterRecords. A VoterRecord has the following format:

  ```
  <voter-identification>

  <voter-data>
  ```
  
  - `<voter-identification>` is a unique string for this voter. This string should be randomly generated and unpredictable.

  - `<voter-data>` is a 1-line seperated (`\n`) list of key value data with the format of `<key>=<value>`.

#### VotersList Service Paths

- `/admins`  View Administrators along with their public keys and roles (auditor, administrator, agent)
- `/list/<voters-list-id>` View a full VoterList Document. New Documents are PUT to this path by Administrators. 
- `/list/<voters-list-id/<voter-id>` View a full voter record, including their public key. This path is used by voters to POST their public key records.
