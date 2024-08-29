#!/bin/bash

narg=$#

if [ ${narg} != 2 ]
then
    echo "Error : expected 2 arguments, got ${narg}."
    exit 1 
fi


filesdir=$1
if [ ! -d ${filesdir} ]
then
    echo "Error : ${filesdir} is not a directory."
    exit 1
fi

searchstr=$2
nfiles=$( find ${filesdir} -type f | wc -l )
nlines=$( grep ${searchstr} -r ${filesdir} | wc -l )
echo "The number of files are ${nfiles} and the number of matching lines are ${nlines}."

exit 0