#!/bin/sh
# Script needs already running server at host 0.0.0.0 and port 2023. Mode(tcp/udp) is specified by 1st argument.
# ipkcpc needs to be compiled

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

BIN=../ipkcpc
count=1

echo "Testing $1."
if [ $1 = "udp" ] || [ $1 = "tcp" ] 
then
    for d in ./$1/*/ ; do
        printf "Test $count:\t"
        $BIN $(eval "cat ./$1/$count/params") -m $1 <./$1/$count/input >./$1/$count/prog_output 2>&1
        DIFF=$(diff ./$1/$count/prog_output ./$1/$count/output) 
        if [ "$DIFF" ] 
        then
            echo -e "${RED}FAILED${NC}"
            echo "Got:"
            eval "cat ./$1/$count/prog_output"
            echo "----------------------------------"
            echo "Was supposed to get:"
            eval "cat ./$1/$count/output"
        else
            echo -e "${GREEN}PASSED${NC}"
            rm -f ./$1/$count/prog_output
        fi
        let count++
    done
else
    echo "1st argument needs to be 'udp or 'tcp'!"
fi
