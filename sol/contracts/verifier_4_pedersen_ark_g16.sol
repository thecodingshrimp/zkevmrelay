// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0af9c5f50acf98c818f85f45260e3efdcf9554fdcf94a51ec9b7d4a18f50bea7), uint256(0x2610bde67fcdc2e001705a2ff6a005926c61b1f1bc08cb8a2f693ac75fc05558));
        vk.beta = Pairing.G2Point([uint256(0x164cb80f268000b50640e63b9bc084a72f6613b08f7e100286eda7110bbbf377), uint256(0x2f04cacb4edaafe9535736d383154e3900fcf0dcc5bc7237155ecbe66ca7df14)], [uint256(0x251ee472e4f04b1d3b7d3270407a9e66622b3a2cc28791d9adca603e4b9eb075), uint256(0x2f3afec2124f0a95512ab033582ca7496220b0a3142520977029b0d8d86ab813)]);
        vk.gamma = Pairing.G2Point([uint256(0x16925211d3cd5dd2ab4434b91d15c5e5a8ef386b1a1e277c6d5ffcf40d852029), uint256(0x26eb4791305e7f934e63324052d3522639cccf8cdba8631834f757f421f8f1cb)], [uint256(0x25e4bf2cafc085c00516ea08e203affb3142bbdac67d4885862f5e8e72446640), uint256(0x080e0559fdbf265516d3c1826051c80c35ca8a36e794d618f6d440913a6fcf77)]);
        vk.delta = Pairing.G2Point([uint256(0x0e8bbeb12b285bf9d7eab00955c4d4279696b56554f6bb45133db81b3aff935c), uint256(0x0bac4ce28a056d32a81001604b70a1dffabe0d22ec185082bde01493e26fe538)], [uint256(0x2d67f9ecc80e89e207b2603953dbc334b447ba79a80750747086e17e12dc70ed), uint256(0x2a6b88ddef2473b4cb9e0ca35bd76b2b94bf0809353aa4ed82dbfcd34b5174d8)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1b9c28a6a6ad33c9d1bc830af258de3cf27303df40797874164abf02acf0c625), uint256(0x26db4878e6b7ac087e8ce3cdd524a8e6a09119245bf4fe08ce8bf0a2fc3f8a44));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x12b1591fd2eead8891016110f5570a155f98263bf9217ffb1526179c01aca726), uint256(0x0b38ce89f5f3c3964561b76e6cd4f7c6f055558b106b2d1fdcd6b2d6ad6431e7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x20d02be4fa2fa19051d310f8b36f2ece2f86cfa778c58568343e4ef96d2d500a), uint256(0x18b945baf4fb31899f4530a871fc63bd47503ead1e9df01a18a788c17fd749a9));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x267cc88b72592773e26d94057bb53cafb60a586768f7fd78d0694ac11684a724), uint256(0x29434ef854623d9501d9f10bd052938d16761abacfa68333c7079e3a14befb23));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x175775e99ae51fbbea445e9b2fec3a5618e594981cfe193716446e83b2825095), uint256(0x29aaa48fc8fffb5002124b393d43418b1eca7e91dccf989ce8fa75ecab1dde9c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1a9b14e3915003118e0e6e67796daf92fa9df358ba705d92667e715f8ff275ea), uint256(0x1a85079c6528ed5ebd4db1104cbc4e77c945d96e0352b72dfa7a21876ed70c27));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x08420091dcd9ad3ee68bb1c6a4866e5f0fed45556686839de9f569ca3b9d850a), uint256(0x0bb6402cc20b1aabfa0e14337fc2022f27fadbb46432e8688cbd0305969a4212));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2cc8d7825afbe65e1a69f95680a3dcc8cd8f5b5350dcd2d9ff57b31a01fab304), uint256(0x10b20ab01c9b683152039bcd1fd72bc0956b2f58e3008f34fb26abb9940a2a6a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x028e4c36e63a6211173685e7c51a54da954be58a3b017d1118c10b9caf442811), uint256(0x06640dbdaf0be00291e9959f6e76e5728eb12230f912a74cb5262cbf95504e29));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x227280f053a417da3bbee2d0f83e5625dbf3fa8b18292c68c9c45806a12bf4d8), uint256(0x25261d62a259b7fe87126043c18e74e9323f15902596c4bd936aa9f693bb4c58));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2ffee2d0e56e7bf0a406ae085f04c4e75be4f3921b18d09df6d4c8e730850c65), uint256(0x05b64485537cc81245e80d406d51f90d6daa1dcb66899fa60b2548ad623d2eb6));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1add955bd32f0fd5a83cd51cfb52e53b827869ed0936ef179aa47de0701980a7), uint256(0x03993384602ec264f02aa45dd43442ccf7b2d6aae3e4a78a74d01b5296eedfd2));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x06bc617bc7e39ea5ff53aba78d9daab18c484a00198ed10f26a4bafac758a987), uint256(0x1d6f755f3bbd61ddcfdc120730ffcd5078add26c7ab2b506c1f074424dd98980));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x03463c7609046ef9f706f28d93cdb24cdb7f62282b56da7c72ff3d80ae426c4d), uint256(0x044f89108a01ab51ad3d3708d025ab76a039025c69a6cf7e621ec5047ddcb400));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x097e0bfc8b324522e1e3bec86e3ea07f92638978ab52731f7a0c6dd848f4fcaf), uint256(0x172fa540a6a4367580f52253d39409cb981afb5a870cd76cd934313551100503));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2aee6786bf424548a03d2f0332496fbc28b78e8bf80524363f0469f728984007), uint256(0x130303d3f5d4dcca90654ec61f6159a64bc5adab1953bcffe4a730927f85de24));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x04010127f07a834057a2c829eea99a899f42f40bf63989f81dfa6e3436255a6d), uint256(0x19a333379491c4987992a7d57981ef47ceed824522d7cd2520d766cda1ad581a));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2cc9df61f852e00f48f83afa026b80ea8eedf349de3cd18d71519208f12c34eb), uint256(0x283e02496d5d580141571e534ce828034d72b63c5f94edd0949d4c0077c847b6));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1dd155e79f834a0775e36b93e38837aec8c5bc8e2ebbc69f58b1097fb32cc59a), uint256(0x2e26cf5bafff82cee4cbc8f612b6b301882239f584d28cdf3d2db687a8e7a0e3));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0c6ee06f8c34ab475ffbbfcd9f54116e1e50f984a6e3ddaa504a8f785c929d56), uint256(0x1a7444b9f235a14531e0b63063aaa72e555a1328fecb227ab75ca132f172ee00));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1089c479516f1dcc82e40c8899ba040bec9e4b7c3003b8d8275450d674f2b4ca), uint256(0x114ce43a0a10364601cc2210696a2a19d06b0a0a9e58d52eba11beec38ee5b5c));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[20] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](20);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
