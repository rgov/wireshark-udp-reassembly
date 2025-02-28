#!/bin/bash
set -eu -o pipefail

# Use text2pcap to generate a pcap from the input file
text2pcap -F pcap -D -u 14641,14641 inputs.txt inputs.pcap

# Use tshark to dissect the packets using our dissector
tshark -X lua_script:pascal.lua -V -O pascal -r inputs.pcap > dissected.txt

# The -v flag prints the dissected output
if [[ "${1:-}" = "-v" ]]; then
    cat dissected.txt
    exit
fi

# Otherwise, diff with the expected output
set +e
diff expected.txt dissected.txt
STATUS=$?
if [ $STATUS -eq 0 ]; then
    echo "Passed!"
fi
exit $STATUS
