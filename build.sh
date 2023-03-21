#!/bin/bash

cd "$(dirname "$0")" || exit 1

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  g++ src/libbottom.cpp -I$JAVA_HOME/include/linux -I$JAVA_HOME/include -o libbottom.so -std=c++17 -shared -pthread -fPIC  
elif [[ "$OSTYPE" == "darwin"* ]]; then
  g++ src/libbottom.cpp -I$JAVA_HOME/include/darwin -I$JAVA_HOME/include -o libbottom.so -std=c++17 -shared -pthread
else
  echo "Unsupported OS"
  exit 1
fi