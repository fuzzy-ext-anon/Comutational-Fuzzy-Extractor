#!/bin/bash
while getopts 'm:s:e:' OPTION; do
    case "$OPTION" in
        m) 
            MESSAGE=${OPTARG}
            echo "Message is ${MESSAGE}"
            ;;
        s)
            SEED=${OPTARG}
            echo "Seed is ${SEED}"
            ;;
        e)
            ERROR=${OPTARG}
            echo "Error rate is ${ERROR}"
            ;;
        # ?)
        #     echo "script usage: $(basename \$0) -m path/to/message.src -s seed_integer -e error_rate_double"
        #     exit 1
        #     ;;
    esac
done

# Prepare 5G parity check matrix (612,198)
PCHK=./parity.pchk
if [ -f "$FILE" ]; then
    ./alist-to-pchk NR_1_4_18.alist parity.pchk
    ./make-gen parity.pchk gen.gen dense
fi

FILENAME="temp${RANDOM}.src"

# Put message into a temp file
echo ${MESSAGE} >> ${FILENAME}

# Encode the message and send it to transmit
# Assuming SEED is an integer and ERROR is a double
# Populate encoded message with errors and send to stdout
./encode parity.pchk gen.gen ${FILENAME} - \
| ./transmit - - "${SEED}" bsc "${ERROR}" \
| cat - 

# Delete temp file
rm ${FILENAME}