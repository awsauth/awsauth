#!/bin/bash

# Set Path

PYTHON="/usr/bin/python"

# Auxiliary Functions

function contains(){  
    local n=$#
    local value=${!n}
    for ((i=1;i < $n;i++)) 
    do
	:
        if [ "${!i}" == "${value}" ]; then
            echo "y"
            return 0
        fi
    done
    echo "n"
    return 1
}

# Main program


if [[ $(contains "$@" "-t") == "y" || $(contains "$@" "--teleport") == "y" ]]; then

$PYTHON awsauth.py $@ 

    if [ $? -eq 0 ]; then
        exit 0
    else
        exit 1 
    fi
else 

$PYTHON awsauth.py $@

    if [ $? -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
fi
