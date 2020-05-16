#!/bin/sh
sleep 10000 &
unzip ./samples.zip
python ./emotet_cff_deobfuscate/emotet_cff_deobfuscate.py ./emotet.unp1.exe
