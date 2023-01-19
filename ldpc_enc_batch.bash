#!/bin/bash
while getopts 's:e:f:' OPTION; do
    case "$OPTION" in
        s)
            SEED=${OPTARG}
            # echo "Seed is ${SEED}"
            ;;
        e)
            ERROR=${OPTARG}
            # echo "Error rate is ${ERROR}"
            ;;
        f)
            CLASS=${OPTARG}
            ;;

    esac
done

# Prepare 5G parity check matrix (612,198)
PCHK=./parity.pchk
if [ -f "$FILE" ]; then
    ./alist-to-pchk NR_1_4_18.alist parity.pchk
    ./make-gen parity.pchk gen.gen dense
fi

FILE_ENC="e${CLASS}.enc"
FILE_REC="r${CLASS}.rec"

# Assuming SEED is an integer and ERROR is a double
# Populate encoded message with errors and send to stdout
./transmit ${FILE_ENC} ${FILE_REC} "${SEED}" bsc "${ERROR}"
