#!/bin/bash

# save current dir
prev_dir=$(pwd)
# go to the directory of the script
cd "$(dirname "$0")"
cd ../sol

# setup constants
proving_schemes=("g16" "gm17" "marlin")
hash_functions=("poseidon" "pedersen")

# 1. generate relay_contracts
MAX_BATCH_SIZE=5
if [[ -n $1 ]]
then
    MAX_BATCH_SIZE=$1
fi
generate_contracts() {
    local max_batch_size=$1
    local hash_function=$2
    local -n local_proving_schemes=$3
    local backend=$4

    # generate relay contracts for all batch sizes and all verifiers.
    for (( i = 0; i < ${max_batch_size}; i++))
    do
        curr_batch_size=$(($i+1))
        for proving_scheme in "${local_proving_schemes[@]}"
        do
            curr_contract_name="relay_contract_batch_${curr_batch_size}_${hash_function}_${backend}_${proving_scheme}.sol"
            curr_verifer_contract_name="verifier_${curr_batch_size}_${hash_function}_${backend}_${proving_scheme}.sol"
            cp ./contracts/relay_contract.sol ./contracts/${curr_contract_name}
            # replace verifier import
            sed -i "/import/s/verifier_[[:digit:]]_[a-z]*_[a-z]*_[a-z0-9]*.sol/${curr_verifer_contract_name}/g" ./contracts/${curr_contract_name}
            # replace contract name
            sed -i "/contract/s/RelayContract/RelayContract${curr_batch_size}${hash_function^^}${backend^^}${proving_scheme^^}/g" ./contracts/${curr_contract_name}

            # export all BN256G2 libraries from the ark + gm17 generated contracts
            BN256G2_present=$(awk '/library BN256G2/' ./contracts/${curr_verifer_contract_name})
            if [[ -n ${BN256G2_present} ]]
            then
                sed -i '1,396d' ./contracts/${curr_verifer_contract_name}
                sed -i 's,solidity \^0\.8\.0;,solidity \^0\.8\.0;\nimport \"\./bn256g2\.sol\";,g' ./contracts/${curr_verifer_contract_name}
            fi
        done
    done
}

# bellman
bellman_schemes=("g16")
generate_contracts ${MAX_BATCH_SIZE} "pedersen" bellman_schemes "bellman"
generate_contracts $((${MAX_BATCH_SIZE}-1)) "poseidon" bellman_schemes "bellman"

# ark
ark_schemes=("g16" "gm17")
marlin_scheme=("marlin")
generate_contracts ${MAX_BATCH_SIZE} "pedersen" ark_schemes "ark"
generate_contracts $((${MAX_BATCH_SIZE}-1)) "poseidon" ark_schemes "ark"
generate_contracts 1 "pedersen" marlin_scheme "ark"
generate_contracts 3 "poseidon" marlin_scheme "ark"

# todo execute tests
npx hardhat test

# remove all generated relay_contracts for clarity.
rm ./contracts/relay_contract_*
cd ${prev_dir}