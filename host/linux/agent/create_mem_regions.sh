#!/bin/bash
OUTPUT=$(sudo less /proc/iomem | grep "System RAM") 
sudo rm mem_regions.json  &>/dev/null
echo "{
   \"allowed_regions\" : {" > mem_regions.json
COUNTER=0 
while IFS= read -r line; do 
    range=$(echo "${line%%[[:space:]]*}") 
    start=$(echo "${range%%-*}") 
    start_dec=$(echo $((16#${start}))) 
    end=$(echo "${range#*-*}") 
    end_dec=$(echo $((16#${end}))) 
    ((length = end_dec - start_dec)) 
    echo "      \"${COUNTER}\" : {" >> mem_regions.json
    echo "         \"length\" : $length," >> mem_regions.json
    echo "         \"start\" : $start_dec" >> mem_regions.json
    echo "      }," >> mem_regions.json
    let COUNTER=COUNTER+1 
done <<< "$OUTPUT" 
echo "   }
}" >> mem_regions.json