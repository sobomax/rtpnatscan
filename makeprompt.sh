#!/bin/sh

set -e
set -o pipefail

if [ ! ${#} -eq 1 ]
then
  echo "usage: `basename ${0}` message.wav" 1>&2
  exit 1
fi

pname="${1%.*}"
rname="${pname}.raw"

sox "${1}" -r 8000 -c 1 --encoding signed-integer -L "${rname}"
makeann "${rname}" "${pname}"
rm "${rname}"
