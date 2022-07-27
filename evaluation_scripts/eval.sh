#!/bin/bash

# save current dir
prev_dir=$(pwd)
# go to the directory of the script
cd "$(dirname "$0")"

# setup constants
evalDir="$(date +%s)"
if [[ -n $1 ]]
then
    evalDir=$1
fi
timeFormat="%M, %E"
timeOutput="--append -o ./../evaluation_results/${evalDir}"
time_exec=/usr/bin/time
zok_exec=~/.zokrates/bin/zokrates
zok_dir=./../zok
contract_dir=./../sol/contracts
go_exec=/home/leo/go/bin/go
BLOCK_NR=30001
MAX_BATCH_SIZE=5
NUM_RERUNS=1
one_more_pedersen=1
bellman_proving_schemes=("g16")
proving_schemes=("g16" "gm17" "marlin")
hash_functions=("poseidon" "pedersen")
batch_mt_heights=(0 1 2 2 3)
universal_setup_exponents_poseidon=(24 25 26 26)
universal_setup_exponents_pedersen=(26 27 27 28 28)
universal_setup_exponents=(24 25 26 27 28)

# generate arguments
echo "Generate arguments..."
for ((i = 0 ; i < ${MAX_BATCH_SIZE} ; i++))
do
    curr_batch_size=$(($i+1))
    if [[ ! -e ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_block_${BLOCK_NR} ]]
    then
        ${go_exec} run generate_zok_program_args.go ${BLOCK_NR} ${curr_batch_size} > /dev/null 2>&1
    fi
done
echo "Done."

# create new eval dir and evaluation files
if [[ ! -d ./../evaluation_results/${evalDir} ]]
then
    mkdir ./../evaluation_results/${evalDir}
    echo "batch size,memory (kbytes),time,mt hash function" > ./../evaluation_results/${evalDir}/compile.csv
    echo "batch size,mt hash function,constraints" > ./../evaluation_results/${evalDir}/constraints.csv
    echo "batch size,memory (kbytes),time,proving scheme,backend,mt hash function" > ./../evaluation_results/${evalDir}/setup.csv
    echo "exponent of size (2**n),memory (kbytes),time" > ./../evaluation_results/${evalDir}/universal_setup.csv
    echo "batch size,memory (kbytes),time,mt hash function" > ./../evaluation_results/${evalDir}/compute_witness.csv
    echo "batch size,memory (kbytes),time,proving scheme,backend,mt hash function" > ./../evaluation_results/${evalDir}/generate_proof.csv
fi

# echo "Universal Setup"
# # 0. universal-setup for marlin + ark
# for universal_setup_exponent in "${universal_setup_exponents[@]}"
# do
#     if [[ ! -e ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_exponent}.dat ]]
#     then
#         ${time_exec} ${timeOutput}/universal_setup.csv -f "${universal_setup_exponent}, ${timeFormat}" \
#         ${zok_exec} universal-setup \
#         -n $universal_setup_exponent \
#         -u ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_exponent}.dat
#     fi
# done
# echo "Done."

# 1: max_batch_size
# 2: hash_functions
eval_compile() {
    local max_batch_size=$1
    local -n local_hash_functions=$2
    for hash_function in "${local_hash_functions[@]}"
    do
        for ((i = 0 ; i < ${max_batch_size} ; i++))
        do
            # 0. name all parameters.
            local curr_batch_size=$(($i+1))
            program="batch_verifier_${curr_batch_size}_${hash_function}"
            echo "Compile"
            # 1. compile
            # 1.1 adjust batch_verification.zok and witness_hashimoto.zok
            sed -i "s/const u32 BATCH_SIZE = [[:digit:]]/const u32 BATCH_SIZE = ${curr_batch_size}/g" ${zok_dir}/batch_verification.zok
            sed -i "s/const u32 BATCH_MT_HEIGHT = [[:digit:]]/const u32 BATCH_MT_HEIGHT = ${batch_mt_heights[${i}]}/g" ${zok_dir}/batch_verification.zok
            sed -i "/import/s/batch_mt_root_generator_[a-z]*.zok/batch_mt_root_generator_${hash_function}.zok/g" ${zok_dir}/batch_verification.zok
            sed -i "/import/s/datasetitem_proof_verifier_[a-z]*.zok/datasetitem_proof_verifier_${hash_function}.zok/g" ${zok_dir}/witness_hashimoto.zok

            # 1.2 compile
            for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
            do
                ${time_exec} ${timeOutput}/compile.csv -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
                ${zok_exec} compile \
                -i ${zok_dir}/batch_verification.zok \
                -o ${zok_dir}/output/programs/${program} \
                | echo "${curr_batch_size}, ${hash_function}, `awk 'NR==4{print $4;exit;}'`" >> ./../evaluation_results/${evalDir}/constraints.csv
                # awk expects the number of constraints to come in the 4th line as the 4th token from the stdout from zokrates compile
            done
        done
    done
}

# 1: backend
# 2: batch_size
# 3: hash_functions
# 4: proving_schemes
# 5: reruns
eval_rest() {
    local backend=$1
    local max_batch_size=$2
    local -n local_hash_functions=$3
    local -n local_proving_schemes=$4
    local NUM_RERUNS=$5

    for proving_scheme in "${local_proving_schemes[@]}"
    do
        for hash_function in "${local_hash_functions[@]}"
        do
            echo "Hash function: ${hash_function}"
            # 0. get correct universal setup size for marlin + ark
            universal_setup_array=universal_setup_exponents_${hash_function}
            universal_setup_array=${!universal_setup_array}

            for ((i = 0 ; i < ${max_batch_size} ; i++))
            do
                # 0. name all parameters.
                local curr_batch_size=$(($i+1))
                program="batch_verifier_${curr_batch_size}_${hash_function}"
                proving_key="proving_key_${program}_${backend}_${proving_scheme}.key"
                verification_key="verification_key_${program}_${backend}_${proving_scheme}.key"
                verification_contract="verifier_${curr_batch_size}_${hash_function}_${backend}_${proving_scheme}.sol"
                echo "Evaluating batch size ${curr_batch_size}"
                # 2. setup
                for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
                do
                    ${time_exec} ${timeOutput}/setup.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ${backend}, ${hash_function}" \
                    ${zok_exec} setup \
                    -u ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_array[$i]}.dat \
                    -i ${zok_dir}/output/programs/${program} \
                    -p ${zok_dir}/output/keys/${proving_key} \
                    -v ${zok_dir}/output/keys/${verification_key} \
                    --proving-scheme ${proving_scheme} --backend ${backend} \
                    >/dev/null 2>>${zok_dir}/output/errors.txt
                done

                echo "Compute-witness"
                # 3. compute-witness
                for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
                do
                    ${time_exec} ${timeOutput}/compute_witness.csv -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
                    ${zok_exec} compute-witness \
                    -i ${zok_dir}/output/programs/${program} \
                    -o ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${hash_function} \
                    -a $(< ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_block_${BLOCK_NR}) \
                    >/dev/null 2>>${zok_dir}/output/errors.txt
                done

                echo "generate-proof"
                # 4. generate-proof
                for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
                do
                    ${time_exec} ${timeOutput}/generate_proof.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ${backend}, ${hash_function}" \
                    ${zok_exec} generate-proof \
                    -i ${zok_dir}/output/programs/${program} \
                    -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${hash_function} \
                    -p ${zok_dir}/output/keys/${proving_key} \
                    -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${hash_function}_${backend}_${proving_scheme}.json \
                    --proving-scheme ${proving_scheme} --backend ${backend} \
                    >/dev/null 2>>${zok_dir}/output/errors.txt
                done

                echo "export-verifier"
                ${zok_exec} export-verifier \
                    -i ${zok_dir}/output/keys/${verification_key} \
                    -o ${contract_dir}/${verification_contract} \
                    >/dev/null 2>>${zok_dir}/output/errors.txt
            done
        done
    done
}

# actual eval:
eval_compile ${MAX_BATCH_SIZE} hash_functions
# bellman
eval_rest "bellman" ${MAX_BATCH_SIZE} hash_functions bellman_proving_schemes 1
# ark
eval_rest "ark" ${MAX_BATCH_SIZE} hash_functions proving_schemes 1

cd ${prev_dir}