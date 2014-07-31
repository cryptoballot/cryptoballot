# /bin/bash
echo "Cleaning up..."
dropdb 'cryptoballot_webtest_electionclerk'
dropdb 'cryptoballot_webtest_ballotbox'
rm electionclerk
rm ballotbox
