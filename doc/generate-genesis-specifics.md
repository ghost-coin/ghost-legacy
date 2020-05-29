## Reference code to get proper genesis specifics.

```c++
      uint32_t nGenesisTime = 1543578342;
        arith_uint256 test;
        bool fNegative;
        bool fOverflow;
        test.SetCompact(0x207fffff, &fNegative, &fOverflow);
        std::cout << "Test threshold: " << test.GetHex() << "\n\n";
        int genesisNonce = 0;
        uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        for (int i=0;i<40000000;i++) {
            genesis = CreateGenesisBlockRegTest(nGenesisTime, i, 0x207fffff);
            consensus.hashGenesisBlock = genesis.GetHash();
            arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
            if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
                BestBlockHash = consensus.hashGenesisBlock;
                std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
                std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
        	std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
        	std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
        	std::cout << "Genesis Merkle " << genesis.hashMerkleRoot.GetHex() << std::endl;
            }
            TempHashHolding = consensus.hashGenesisBlock;
            if (BestBlockHashArith < test) {
                genesisNonce = i - 1;
                genesis = CreateGenesisBlockRegTest(nGenesisTime, genesisNonce, 0x207fffff);
                break;
            }
        }
        std::cout << "\n";
        std::cout << "\n";
        std::cout << "\n";
        std::cout << "hashGenesisBlock to 0x" << genesis.GetHash().ToString() << std::endl;
        std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
        std::cout << "Genesis Merkle " << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "Genesis hashWitnessMerkleRoot " << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;

        std::cout << "\n";
        std::exit(0);
```
## Instructions
- Change nGenesisTime to match the genesis epoch.
- Set 0x207fffff to the bits you want for genesis.
- After that copy paste the modified code before the asserts.
- Build daemon and execute ghostd,it will give the needed hash and specifics after run is over.