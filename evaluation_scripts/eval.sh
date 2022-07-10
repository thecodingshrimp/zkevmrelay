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
go_exec=go

# create new eval dir
mkdir ./../evaluation_results/${evalDir}

# generate arguments
echo "Generate arguments..."
for i in {1..5}
do
    if [[ ! -e ${zok_dir}/arguments/batch_verifier_$i ]]
    then
        ${go_exec} run generate_zok_program_args.go 30001 $i > /dev/null 2>&1
    fi
done
echo "Done."

echo "batch size,memory (kbytes),time" > ./../evaluation_results/${evalDir}/compile.xlsx
echo "batch size,memory (kbytes),time" > ./../evaluation_results/${evalDir}/setup.xlsx
echo "batch size,memory (kbytes),time" > ./../evaluation_results/${evalDir}/compute_witness.xlsx
echo "batch size,memory (kbytes),time" > ./../evaluation_results/${evalDir}/generate_proof.xlsx

# execute different batches
for i in {1..5}
do
    echo "Evaluating batch size $i"
    echo "Compile"
    # 1. compile
    # 1.1 adjust batch_verification.zok file
    sed -i "s/const u32 BATCH_SIZE = [[:digit:]]/const u32 BATCH_SIZE = $i/g" ${zok_dir}/batch_verification.zok
    # 1.2 compile
    echo "BATCH SIZE $i" >> ./../evaluation_results/${evalDir}/constraints
    for j in {1..5}
    do
        ${time_exec} ${timeOutput}/compile.xlsx -f "$i, ${timeFormat}" ${zok_exec} compile -i ${zok_dir}/batch_verification.zok -o ${zok_dir}/output/batch_verifier_$i  >> ./../evaluation_results/${evalDir}/constraints
    done

    echo "Setup"
    # 2. setup
    for j in {1..5}
    do
        ${time_exec} ${timeOutput}/setup.xlsx -f "$i, ${timeFormat}" ${zok_exec} setup -i ${zok_dir}/output/batch_verifier_$i -p ${zok_dir}/output/proving_key_batch_verifier_$i.key -v ${zok_dir}/output/verification_key_batch_verifier_$i.key #> /dev/null 2>&1
    done

    echo "Compute-witness"
    # 3. compute-witness
    for j in {1..5}
    do
        ${time_exec} ${timeOutput}/compute_witness.xlsx -f "$i, ${timeFormat}" ${zok_exec} compute-witness -i ${zok_dir}/output/batch_verifier_$i -o ${zok_dir}/output/witness_batch_verifier_$i -a $(< ${zok_dir}/arguments/batch_verifier_$i) #> /dev/null 2>&1
    done

    echo "generate-proof"
    # 4. generate-proof
    for j in {1..5}
    do
        ${time_exec} ${timeOutput}/generate_proof.xlsx -f "$i, ${timeFormat}" ${zok_exec} generate-proof -i ${zok_dir}/output/batch_verifier_$i -w ${zok_dir}/output/witness_batch_verifier_$i -p ${zok_dir}/output/proving_key_batch_verifier_$i.key -j ${zok_dir}/output/proof_batch_verifier_$i #> /dev/null 2>&1
    done
done

cd ${prev_dir}