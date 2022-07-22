#!/bin/bash

# save current dir
prev_dir=$(pwd)
# go to the directory of the script
cd "$(dirname "$0")"

# setup constants
evalDir="$(date +%s)"
timeFormat="%M, %E"
timeOutput="--append -o ./../evaluation_results/${evalDir}"
time_exec=/usr/bin/time
zok_exec=~/.zokrates/bin/zokrates
zok_dir=./../zok
contract_dir=./../sol/contracts
go_exec=go
MAX_BATCH_SIZE=1
NUM_RERUNS=1
proving_schemes=("g16" "gm17" "marlin")
hash_functions=("poseidon" "pedersen")
batch_mt_heights=(0 1 2 2 3)

# create new eval dir
mkdir ./../evaluation_results/${evalDir}

# generate arguments
echo "Generate arguments..."
for ((i = 0 ; i < ${MAX_BATCH_SIZE} ; i++))
do
    curr_batch_size=$(($i+1))
    if [[ ! -e ${zok_dir}/arguments/batch_verifier_${curr_batch_size} ]]
    then
        ${go_exec} run generate_zok_program_args.go 30001 ${curr_batch_size} > /dev/null 2>&1
    fi
done
echo "Done."

echo "batch size,memory (kbytes),time,mt hash function" > ./../evaluation_results/${evalDir}/compile.xlsx
echo "batch size,memory (kbytes),time,proving scheme,backend,mt hash function" > ./../evaluation_results/${evalDir}/setup.xlsx
echo "batch size,memory (kbytes),time,mt hash function" > ./../evaluation_results/${evalDir}/compute_witness.xlsx
echo "batch size,memory (kbytes),time,proving scheme,backend,mt hash function" > ./../evaluation_results/${evalDir}/generate_proof.xlsx

# execute different batches
for ((i = 0 ; i < ${MAX_BATCH_SIZE} ; i++))
do
    curr_batch_size=$(($i+1))
    echo $curr_batch_size
    echo "Evaluating batch size ${curr_batch_size}"
    # hash functions
    for hash_function in "${hash_functions[@]}"
    do
        echo "Compile"
        # 1. compile
        # 1.1 adjust batch_verification.zok and witness_hashimoto.zok
        sed -i "s/const u32 BATCH_SIZE = [[:digit:]]/const u32 BATCH_SIZE = ${curr_batch_size}/g" ${zok_dir}/batch_verification.zok
        sed -i "s/const u32 BATCH_MT_HEIGHT = [[:digit:]]/const u32 BATCH_MT_HEIGHT = ${batch_mt_heights[${curr_batch_size}]}/g" ${zok_dir}/batch_verification.zok
        sed -i "/import/s/batch_mt_root_generator_[a-z]*.zok/batch_mt_root_generator_${hash_function}.zok/g" ${zok_dir}/batch_verification.zok
        sed -i "/import/s/datasetitem_proof_verifier_[a-z]*.zok/datasetitem_proof_verifier_${hash_function}.zok/g" ${zok_dir}/witness_hashimoto.zok

        # 1.2 compile
        echo "BATCH SIZE ${curr_batch_size}, hash function ${hash_function}" >> ./../evaluation_results/${evalDir}/constraints
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/compile.xlsx -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
             ${zok_exec} compile \
              -i ${zok_dir}/batch_verification.zok \
              -o ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
              >> ./../evaluation_results/${evalDir}/constraints
        done

        echo "Setup"
        # 2. setup
        # 2.1 backend bellman
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/setup.xlsx -f "${curr_batch_size}, ${timeFormat}, g16, bellman,${hash_function}" \
             ${zok_exec} setup \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
              -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${hash_function}_bellman_g16.key \
              -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${hash_function}_bellman_g16.key \
              --proving-scheme g16 --backend bellman #> /dev/null 2>&1
        done
        # 2.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
            do
                ${time_exec} ${timeOutput}/setup.xlsx -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                 ${zok_exec} setup \
                  -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
                  -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${hash_function}_ark_${proving_scheme}.key \
                  -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${hash_function}_ark_${proving_scheme}.key \
                  --proving-scheme ${proving_scheme} --backend ark #> /dev/null 2>&1
            done
        done

        echo "Compute-witness"
        # 3. compute-witness
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/compute_witness.xlsx -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
             ${zok_exec} compute-witness \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
              -o ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${hash_function} \
              -a $(< ${zok_dir}/arguments/batch_verifier_${curr_batch_size}) #> /dev/null 2>&1
        done

        echo "generate-proof"
        # 4. generate-proof
        # 4.1 backend bellman
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/generate_proof.xlsx -f "${curr_batch_size}, ${timeFormat}, g16, bellman, ${hash_function}" \
             ${zok_exec} generate-proof \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
              -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${hash_function} \
              -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${hash_function}_bellman_g16.key \
              -j ${zok_dir}/output/proof_batch_verifier_${curr_batch_size}_${hash_function} \
              --proving-scheme g16 --backend bellman #> /dev/null 2>&1
        done
        # 4.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
            do
                ${time_exec} ${timeOutput}/generate_proof.xlsx -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                 ${zok_exec} generate-proof \
                  -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${hash_function} \
                  -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${hash_function} \
                  -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${hash_function}_ark_${proving_scheme}.key \
                  -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${hash_function} \
                  --proving-scheme ${proving_scheme} --backend ark #> /dev/null 2>&1
            done
        done

        # 5. export verifier
        # 5.1 backend bellman
        ${zok_exec} export-verifier \
         -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${hash_function}_bellman_g16.key
         -o ${contract_dir}/verifier_${curr_batch_size}_${hash_function}_bellman_g16.sol
        # 5.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            ${zok_exec} export-verifier \
             -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${hash_function}_ark_${proving_scheme}.key
             -o ${contract_dir}/verifier_${curr_batch_size}_${hash_function}_ark_${proving_scheme}.sol
        done
    done
done

cd ${prev_dir}