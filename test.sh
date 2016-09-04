#!/bin/sh

#
# Basic sanity test
#
./chch --encrypt < plaintext.txt > /tmp/TEST-ENC.bin
./chch -d < /tmp/TEST-ENC.bin > /tmp/TEST-DEC.txt
diff plaintext.txt /tmp/TEST-DEC.txt
RETCODE=$?
if [ $RETCODE != 0 ] ; then
	echo "FAILED:  basic sanity"
	exit 1
fi
rm /tmp/TEST-ENC.bin /tmp/TEST-DEC.txt



echo "All tests OK"
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
	diff ${PLAINTEXT}.enc ${TMPDIR}/${PLAINTEXT}.enc
	RETCODE=$?
	echo "diff RETCODE = $RETCODE"
done
