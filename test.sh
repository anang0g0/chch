#!/bin/sh

SELF=$0

#
# Basic sanity test
#
./chch --encrypt --pass @.passphrase < plaintext.txt > /tmp/TEST-ENC.bin
./chch -dp @.passphrase  < /tmp/TEST-ENC.bin > /tmp/TEST-DEC.txt
>/dev/null diff -q plaintext.txt /tmp/TEST-DEC.txt
RETCODE=$?
if [ $RETCODE != 0 ] ; then
	echo "[$SELF] FAILED:  basic sanity test"
	exit 1
fi
rm /tmp/TEST-ENC.bin /tmp/TEST-DEC.txt



echo "[$SELF] All tests OK"
exit 0



#
# Loop through all test vectors
#
TMPDIR=./tmp-testrun
rm -rf ${TMPDIR}
mkdir ${TMPDIR}

PASSPHRASE="bananas12345"

PLAINTEXTS_ARRAY=(vec1 vec2 vec3)

for PLAINTEXT in ${PLAINTEXTS_ARRAY[@]}; do
	../simple < $PLAINTEXT > ${TMPDIR}/${PLAINTEXT}.enc
	>/dev/null diff -q ${PLAINTEXT}.enc ${TMPDIR}/${PLAINTEXT}.enc
	RETCODE=$?
	echo "[$SELF] diff RETCODE = $RETCODE"
done
