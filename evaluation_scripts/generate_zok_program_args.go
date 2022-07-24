package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/thecodingshrimp/zkevmrelay/ethash"
	"go.uber.org/zap"
)

const (
	ethash_dir = "./../ethash" // directory with ethash files
	zok_dir    = "./../zok"    // directory with zokrates files
)

func main() {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()
	if len(os.Args) != 3 {
		sugar.Fatalw("Usage: program <block_nr> <max_batch_size>")
	}
	BLOCK_NR, err := strconv.Atoi(os.Args[1])
	if err != nil {
		sugar.Fatalw(err.Error())
	}
	MAX_BATCH_SIZE, err := strconv.Atoi(os.Args[2])
	if err != nil {
		sugar.Fatalw(err.Error())
	}

	// connect to client
	geth, err := ethclient.Dial("https://mainnet.infura.io/v3/6884b6e0a90d42d291b8d3faca1a9ad6")
	if err != nil {
		sugar.Fatalw("Could not connect to eth client.")
	}

	for i := 0; i < MAX_BATCH_SIZE; i++ {
		// generate parameters for zokrates program
		zkProgramArguments := ethash.GenerateZokratesBatchParameters(uint64(BLOCK_NR+i), uint64(i+1), geth, ethash_dir, logger)

		// write arguments to file
		argumentPath := fmt.Sprintf("%s/arguments/batch_verifier_%d_epoch_%d", zok_dir, i+1, int(int(BLOCK_NR)/30000))

		err = ioutil.WriteFile(argumentPath, []byte(zkProgramArguments), 0666)
		if err != nil {
			sugar.Fatalw(err.Error())
		}
	}
}
