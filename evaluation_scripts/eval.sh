#!/bin/bash

evalFile="$(date +%s)"
timeFormat="| %M | %E |"
timeOutput="--append -o ./../evaluation_results/${evalFile}"
time_exec=/usr/bin/time
zok_exec=~/.zokrates/bin/zokrates
zok_dir=./../zok
go_exec=go

# generate arguments
echo "Generate arguments..."
for i in {1..5}
do
    ${go_exec} run generate_zok_program_args.go 30001 $i > /dev/null 2>&1
done
echo "Done."

echo "| batch size | memory (kbytes) |    time |" > ./../evaluation_results/${evalFile}_compile
echo "|------------|----------------:|--------:|" >> ./../evaluation_results/${evalFile}_compile
echo "| batch size | memory (kbytes) |    time |" > ./../evaluation_results/${evalFile}_setup
echo "|------------|----------------:|--------:|" >> ./../evaluation_results/${evalFile}_setup
echo "| batch size | memory (kbytes) |    time |" > ./../evaluation_results/${evalFile}_compute_witness
echo "|------------|----------------:|--------:|" >> ./../evaluation_results/${evalFile}_compute_witness
echo "| batch size | memory (kbytes) |    time |" > ./../evaluation_results/${evalFile}_generate_proof
echo "|------------|----------------:|--------:|" >> ./../evaluation_results/${evalFile}_generate_proof

# execute different batches
for i in {1..5}
do
    echo "Evaluating batch size $i"
    echo "Compile"
    # 1. compile
    # 1.1 adjust batch_verification.zok file
    sed -i "s/const u32 BATCH_SIZE = \d/const u32 BATCH_SIZE = $i/" ${zok_dir}/batch_verification.zok
    # 1.2 compile
    ${time_exec} ${timeOutput}_compile -f "|$i ${timeFormat}" ${zok_exec} compile -i ${zok_dir}/batch_verification.zok -o ${zok_dir}/output/batch_verifier_$i  >> ./../evaluation_results/${evalFile}_constraints

    echo "Setup"
    # 2. setup
    ${time_exec} ${timeOutput}_setup -f "|$i ${timeFormat}" ${zok_exec} setup -i ${zok_dir}/output/batch_verifier_$i -p ${zok_dir}/output/proving_key_batch_verifier_$i.key -v ${zok_dir}/output/verification_key_batch_verifier_$i.key

    echo "Compute-witness"
    # 3. compute-witness
    ${time_exec} ${timeOutput}_compute_witness -f "|$i ${timeFormat}" ${zok_exec} compute-witness -i ${zok_dir}/output/batch_verifier_$i -o ${zok_dir}/output/witness_batch_verifier_$i -a $(< ${zok_dir}/arguments/batch_verifier_$i)

    echo "generate-proof"
    # 4. generate-proof
    ${time_exec} ${timeOutput}_generate_proof -f "|$i ${timeFormat}" ${zok_exec} generate-proof -i ${zok_dir}/output/batch_verifier_$i -w ${zok_dir}/output/witness_batch_verifier_$i -p ${zok_dir}/output/proving_key_batch_verifier_$i.key -j ${zok_dir}/output/proof_batch_verifier_$i
done
