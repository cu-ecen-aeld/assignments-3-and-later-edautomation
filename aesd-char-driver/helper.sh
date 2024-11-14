#!/bin/sh


sudo ./aesdchar_unload
make clean
make
sudo ./aesdchar_load

