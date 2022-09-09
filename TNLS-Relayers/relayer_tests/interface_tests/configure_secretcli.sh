#!/bin/bash

chain_id=${CHAINID:-secretdev-1}

secretcli config chain-id "$chain_id"
secretcli config keyring-backend test
secretcli config output json
secretcli config node http://localhost:26657
secretcli config broadcast-mode sync

# print out config settings to confirm them
echo -e "\033[1msecretd config:\033[0m"
secretcli config
echo

# print out status to confirm connection
echo -e "\033[1msecretd status:\033[0m"
SGX_MODE=SW secretcli status
echo

a_mnemonic="grant rice replace explain federal release fix clever romance raise often wild taxi quarter soccer fiber love must tape steak together observe swap guitar"
b_mnemonic="jelly shadow frog dirt dragon use armed praise universe win jungle close inmate rain oil canvas beauty pioneer chef soccer icon dizzy thunder meadow"
c_mnemonic="chair love bleak wonder skirt permit say assist aunt credit roast size obtain minute throw sand usual age smart exact enough room shadow charge"
d_mnemonic="word twist toast cloth movie predict advance crumble escape whale sail such angry muffin balcony keen move employ cook valve hurt glimpse breeze brick"

echo $a_mnemonic | secretcli keys add a --recover > /dev/null 2>&1
echo $b_mnemonic | secretcli keys add b --recover > /dev/null 2>&1
echo $c_mnemonic | secretcli keys add c --recover > /dev/null 2>&1
echo $d_mnemonic | secretcli keys add d --recover > /dev/null 2>&1

declare -a KEY=(a b c d)

declare -A FROM=(
    [a]='-y --from a'
    [b]='-y --from b'
    [c]='-y --from c'
    [d]='-y --from d'
)

declare -A ADDRESS=(
    [a]="$(secretcli keys show --address a)"
    [b]="$(secretcli keys show --address b)"
    [c]="$(secretcli keys show --address c)"
    [d]="$(secretcli keys show --address d)"
)
echo -e "\033[1mAdded keys:\033[0m"
echo "a, address: ${ADDRESS[a]}"
echo "b, address: ${ADDRESS[b]}"
echo "c, address: ${ADDRESS[c]}"
echo "d, address: ${ADDRESS[d]}"
echo
