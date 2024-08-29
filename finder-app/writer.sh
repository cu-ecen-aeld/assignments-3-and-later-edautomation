#!/bin/bash

narg=$#

if [ ${narg} != 2 ]
then
    echo "Error : expected 2 arguments, got ${narg}."
    exit 1
fi

writefile=$1
if [ ! -e ${writefile} ]
then 
    writedir=$( dirname ${writefile})
    if [ ! -d ${writedir} ]
    then
        echo "Creating directory ${writedir}..."
        mkdir -p ${writedir}
        if [ $? != 0 ]
        then
            echo "Error : could not create directory ${writedir}"
            exit 1
        fi
    fi
    echo "Creating ${writefile}..."
    touch ${writefile}
    if [ $? != 0 ]
    then
        echo "Error : could not create file ${writefile}"
        exit 1
    fi
    echo "Done creating file"
fi

writestr=$2
echo ${writestr} > ${writefile}