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
MAX_BATCH_SIZE=4
NUM_RERUNS=1
one_more_pedersen=1
proving_schemes=("g16" "gm17" "marlin")
hash_functions=("poseidon" "pedersen")
batch_mt_heights=(0 1 2 2 3)
universal_setup_exponents_poseidon=(24 25 26 26)
universal_setup_exponents_pedersen=(26 27 27 28 28)
universal_setup_exponents=(24 25 26 27 28)
EPOCH=$((${BLOCK_NR}/30000))

# generate arguments
echo "Generate arguments..."
for ((i = 0 ; i < ${MAX_BATCH_SIZE} ; i++))
do
    curr_batch_size=$(($i+1))
    if [[ ! -e ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_epoch_${EPOCH} ]]
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

echo "Universal Setup"
# 0. universal-setup for marlin + ark
for universal_setup_exponent in "${universal_setup_exponents[@]}"
do
    ${time_exec} ${timeOutput}/universal_setup.csv -f "${universal_setup_exponent}, ${timeFormat}" \
     ${zok_exec} universal-setup \
     -n $universal_setup_exponent \
     -u ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_exponent}.dat
done
echo "Done."

# execute different batches
for ((i = 0 ; i < ${MAX_BATCH_SIZE} ; i++))
do
    curr_batch_size=$(($i+1))
    echo "Evaluating batch size ${curr_batch_size}"
    # hash functions
    for hash_function in "${hash_functions[@]}"
    do
        echo "Hash function: ${hash_function}"
        # 0. get correct universal setup size for marlin + ark
        universal_setup_array=universal_setup_exponents_${hash_function}
        universal_setup_array=${!universal_setup_array}
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
              -o ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              | echo "${curr_batch_size}, ${hash_function}, `awk 'NR==4{print $4;exit;}'`" >> ./../evaluation_results/${evalDir}/constraints.csv
              # awk expects the number of constraints to come in the 4th line as the 4th token from the stdout from zokrates compile
        done

        echo "Setup"
        # 2. setup
        # 2.1 backend bellman
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/setup.csv -f "${curr_batch_size}, ${timeFormat}, g16, bellman,${hash_function}" \
             ${zok_exec} setup \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
              -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
              --proving-scheme g16 --backend bellman \
              >/dev/null 2>>${zok_dir}/output/errors.txt
        done
        # 2.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
            do
                ${time_exec} ${timeOutput}/setup.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                 ${zok_exec} setup \
                  -u ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_array[$i]}.dat \
                  -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                  -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                  -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                  --proving-scheme ${proving_scheme} --backend ark \
              >/dev/null 2>>${zok_dir}/output/errors.txt
            done
        done

        echo "Compute-witness"
        # 3. compute-witness
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/compute_witness.csv -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
             ${zok_exec} compute-witness \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              -o ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              -a $(< ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_${EPOCH}) \
              >/dev/null 2>>${zok_dir}/output/errors.txt
        done

        echo "generate-proof"
        # 4. generate-proof
        # 4.1 backend bellman
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/generate_proof.csv -f "${curr_batch_size}, ${timeFormat}, g16, bellman, ${hash_function}" \
             ${zok_exec} generate-proof \
              -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
              -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
              -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16 \
              --proving-scheme g16 --backend bellman \
              >/dev/null 2>>${zok_dir}/output/errors.txt
        done
        # 4.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
            do
                ${time_exec} ${timeOutput}/generate_proof.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                 ${zok_exec} generate-proof \
                  -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                  -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                  -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                  -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme} \
                  --proving-scheme ${proving_scheme} --backend ark \
                  >/dev/null 2>>${zok_dir}/output/errors.txt
            done
        done

        echo "export-verifier"
        # 5. export verifier
        # 5.1 backend bellman
        ${zok_exec} export-verifier \
         -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
         -o ${contract_dir}/verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.sol
        # 5.2 backend ark
        for proving_scheme in "${proving_schemes[@]}"
        do
            ${zok_exec} export-verifier \
             -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
             -o ${contract_dir}/verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.sol \
             >/dev/null 2>>${zok_dir}/output/errors.txt
        done
    done
done

# check if one more round with pedersen (pedersen uses less RAM than poseidon)
if [[ $one_more_pedersen -eq 1]]
then
    curr_batch_size=$(($MAX_BATCH_SIZE+1))
    hash_function="pedersen"
    if [[ ! -e ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_${EPOCH} ]]
    then
        ${go_exec} run generate_zok_program_args.go ${BLOCK_NR} ${curr_batch_size} > /dev/null 2>&1
    fi
    echo "Evaluating one more batch size ($curr_batch_size) with hash function pedersen."
    echo "Compile"
    # 0. get correct universal setup size for marlin + ark
    universal_setup_array=universal_setup_exponents_pedersen
    universal_setup_array=${!universal_setup_array}
    # 1. compile
    # 1.1 adjust batch_verification.zok and witness_hashimoto.zok
    sed -i "s/const u32 BATCH_SIZE = [[:digit:]]/const u32 BATCH_SIZE = ${curr_batch_size}/g" ${zok_dir}/batch_verification.zok
    sed -i "s/const u32 BATCH_MT_HEIGHT = [[:digit:]]/const u32 BATCH_MT_HEIGHT = ${batch_mt_heights[${MAX_BATCH_SIZE}]}/g" ${zok_dir}/batch_verification.zok
    sed -i "/import/s/batch_mt_root_generator_[a-z]*.zok/batch_mt_root_generator_${hash_function}.zok/g" ${zok_dir}/batch_verification.zok
    sed -i "/import/s/datasetitem_proof_verifier_[a-z]*.zok/datasetitem_proof_verifier_${hash_function}.zok/g" ${zok_dir}/witness_hashimoto.zok

    # 1.2 compile
    for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
    do
        ${time_exec} ${timeOutput}/compile.csv -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
            ${zok_exec} compile \
            -i ${zok_dir}/batch_verification.zok \
            -o ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            | echo "${curr_batch_size}, ${hash_function}, `awk 'NR==4{print $4;exit;}'`" >> ./../evaluation_results/${evalDir}/constraints.csv
            # awk expects the number of constraints to come in the 4th line as the 4th token from the stdout from zokrates compile
    done

    echo "Setup"
    # 2. setup
    # 2.1 backend bellman
    for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
    do
        ${time_exec} ${timeOutput}/setup.csv -f "${curr_batch_size}, ${timeFormat}, g16, bellman,${hash_function}" \
            ${zok_exec} setup \
            -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
            -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
            --proving-scheme g16 --backend bellman \
            > /dev/null 2>>${zok_dir}/errors.txt
    done
    # 2.2 backend ark
    for proving_scheme in "${proving_schemes[@]}"
    do
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/setup.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                ${zok_exec} setup \
                -u ${zok_dir}/output/universal_setups/universal_setup_${universal_setup_array[$i]}.dat \
                -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                -v ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                --proving-scheme ${proving_scheme} --backend ark \
                > /dev/null 2>>${zok_dir}/errors.txt
        done
    done

    echo "Compute-witness"
    # 3. compute-witness
    for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
    do
        ${time_exec} ${timeOutput}/compute_witness.csv -f "${curr_batch_size}, ${timeFormat}, ${hash_function}" \
            ${zok_exec} compute-witness \
            -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            -o ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            -a $(< ${zok_dir}/arguments/batch_verifier_${curr_batch_size}_${EPOCH}) \
            > /dev/null 2>>${zok_dir}/errors.txt
    done

    echo "generate-proof"
    # 4. generate-proof
    # 4.1 backend bellman
    for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
    do
        ${time_exec} ${timeOutput}/generate_proof.csv -f "${curr_batch_size}, ${timeFormat}, g16, bellman, ${hash_function}" \
            ${zok_exec} generate-proof \
            -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
            -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
            -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16 \
            --proving-scheme g16 --backend bellman \
            > /dev/null 2>>${zok_dir}/errors.txt
    done
    # 4.2 backend ark
    for proving_scheme in "${proving_schemes[@]}"
    do
        for ((j = 0 ; j < ${NUM_RERUNS} ; j++))
        do
            ${time_exec} ${timeOutput}/generate_proof.csv -f "${curr_batch_size}, ${timeFormat}, ${proving_scheme}, ark, ${hash_function}" \
                ${zok_exec} generate-proof \
                -i ${zok_dir}/output/programs/batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                -w ${zok_dir}/output/witnesses/witness_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function} \
                -p ${zok_dir}/output/keys/proving_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
                -j ${zok_dir}/output/proofs/proof_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme} \
                --proving-scheme ${proving_scheme} --backend ark \
                > /dev/null 2>>${zok_dir}/errors.txt
        done
    done

    echo "export-verifier"
    # 5. export verifier
    # 5.1 backend bellman
    ${zok_exec} export-verifier \
        -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.key \
        -o ${contract_dir}/verifier_${curr_batch_size}_${EPOCH}_${hash_function}_bellman_g16.sol
    # 5.2 backend ark
    for proving_scheme in "${proving_schemes[@]}"
    do
        ${zok_exec} export-verifier \
            -i ${zok_dir}/output/keys/verification_key_batch_verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.key \
            -o ${contract_dir}/verifier_${curr_batch_size}_${EPOCH}_${hash_function}_ark_${proving_scheme}.sol
    done
fi

cd ${prev_dir}