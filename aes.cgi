#!/bin/bash

echo "Content-Type: text/html"
echo ""

saveIFS=$IFS
IFS='=&'
parm=($QUERY_STRING)
IFS=$saveIFS
declare -A array
for ((i=0; i<${#parm[@]}; i+=2))
do
    array[${parm[i]}]=${parm[i+1]}
done


key=`printf "%b\n" "$(echo ${array[key]} | sed 's/+/ /g; s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\\\x\1/g;')"`
iv=`printf "%b\n" "$(echo ${array[iv]} | sed 's/+/ /g; s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\\\x\1/g;')"`
original=`printf "%b\n" "$(echo ${array[val]} | sed 's/+/ /g; s/%\([0-9a-fA-F][0-9a-fA-F]\)/\\\\x\1/g;')"`

hexkey=$key
hexiv=$iv
result=''
zero="\0"
if [ "${array[mode]}" = 'encrypt' ]
then
  result=`echo -ne ${original}${zero} | openssl enc -e -aes-128-cbc -K ${hexkey} -iv ${hexiv} | xxd -p`
  result=`printf "%b\n" "$(echo ${result} | sed 's/[^0-9a-fA-F]//g')"`
elif [ "${array[mode]}" = 'decrypt' ]
then
  result=`echo ${original} | xxd -r -ps | openssl enc -d -aes-128-cbc -K ${hexkey} -iv ${hexiv}`
fi

echo $result
