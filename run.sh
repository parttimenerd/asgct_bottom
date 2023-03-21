#!/bin/bash

BASEDIR="$( dirname "${BASH_SOURCE[0]}" )"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  java "-agentpath:$BASEDIR/libbottom.so" $@
elif [[ "$OSTYPE" == "darwin"* ]]; then
  java "-agentpath:$BASEDIR/libbottom.so" $@
else
  echo "Unsupported OS"
  exit 1
fi