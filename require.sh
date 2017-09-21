#!/bin/bash
if [ ! $(which rp++) ]
then
    url=""
    dest="/usr/local/bin/rp++"
    #if archtecture is 64bit
    if [[ $(grep lm /proc/cpuinfo) ]]
    then
        if [ $(which rp-lin-x64) ]
        then
            sudo ln -s $(which rp-lin-x64) $dest
        else
            url="https://github.com/downloads/0vercl0k/rp/rp-lin-x64"
            sudo wget $url -O $dest
            sudo chmod 755 $dest
        fi
    #if archtecture is 32bit
    elif [[ $(grep tm /proc/cpuinfo) ]]
    then
        if [ $(which rp-lin-x86) ]
        then
            sudo ln -s $(which rp-lin-x86) $dest
        else
            url="https://github.com/downloads/0vercl0k/rp/rp-lin-x86"
            sudo wget $url -O $dest
            sudo chmod 755 $dest
        fi
    fi
fi
