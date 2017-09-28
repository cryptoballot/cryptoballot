CryptoBallot Demonstration
--------------------------

1. Start Postgres and create databases
    docker-compose up -d
    createdb --host=localhost --username=postgres --port=9856 cryptoballot_demo_electionclerk
    createdb --host=localhost --username=postgres --port=9856 cryptoballot_demo_ballotbox

2. Compile and start electionclerk server
    cd servers
    go build ../../servers/electionclerk
    ./electionclerk --config=electionclerk.conf --set-up-db
    ./electionclerk --config=electionclerk.conf
    >> Enter password: password

3. Create a new election and PUT it to the electionclerk server
    cat bestartist.election
    cryptoballot --key=admin_key.pem admin create bestartist.election
    View election and admin public keys
       http://localhost:8000/election/bestartist
       http://localhost:8000/admins
       http://localhost:8000/publickey

4. Start up ballotbox server
    cd servers
    go build ../../servers/ballotbox
    ./ballotbox --config=ballotbox.conf --set-up-db
    ./ballotbox --config=ballotbox.conf

5. Create some voters:
    openssl genrsa -aes128 -out voter1.pem 4096
    openssl genrsa -aes128 -out voter2.pem 4096

6. Deposit votes with blind-signing
    cat bestartist.1.ballot
    cat bestartist.2.ballot
    cryptoballot --key=voter1.pem voter vote bestartist.1.ballot
    cryptoballot --key=voter2.pem voter vote bestartist.2.ballot

7. Examine election:
    http://localhost:8000/election/bestartist
