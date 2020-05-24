#!/bin/sh
unzip ./samples.zip
python ./emotet_cff_deobfuscate/emotet_cff_deobfuscate.py ./emotet.unp1.exe
