# /bin/bash
echo "Cleaning up..."
dropdb --host=localhost --username=postgres --port=9856 'cryptoballot_webtest_electionclerk'
dropdb --host=localhost --username=postgres --port=9856 'cryptoballot_webtest_ballotbox'
rm electionclerk
rm ballotbox
