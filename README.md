# About

JavaCard applet for secure HMAC generation

# Build

Building require Java 7 file format (51.0), so need to use old JDK.

## Install dependencies

Install packages:
* maven
* ant
* JDK 11

Install java packages:

* `jcardsim-3.0.5.jar`
* Oracle JavaCard SDK 3.0.5u4 `api_classic.jar`

## Build project


```
export JAVA_HOME=/path/to/JDK11
mvn clean
mvn package
sh buildcap.sh
```

# Install

`java -jar gp.jar --key <ISD KEY> --install OTPCard.cap --params 08080606`

Where params:
* max amount of secrets
* max secret name length
* PIN attempts count
* Admin PIN attempts count

# Usage

Default PIN `123456`, default admin PIN `12345678`
