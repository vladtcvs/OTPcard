#!/bin/bash

rm -f OTPCard.cap
mkdir buildcap
cp build.xml buildcap/
cp -r ext/oracle_javacard_sdks/jc305u4_kit buildcap/
cd buildcap
jar xf ../target/OTPCard-0.1.jar
ant
mv OTPCard.cap ..
cd ..
rm -r buildcap
