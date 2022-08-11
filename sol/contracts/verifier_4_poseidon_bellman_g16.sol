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
        vk.alpha = Pairing.G1Point(uint256(0x084ee240a237bc5f805550039bb2d04b11afd69e70b37760687fd5d3012fd5c0), uint256(0x028e887a77bf98ef117ca01665b8654efb419160252c0404787b4b0422b0ea89));
        vk.beta = Pairing.G2Point([uint256(0x2a7e7821a4cf8a74d89762e5ce6772e11740ac8da3dfc046e6f2ac889b5b2cf5), uint256(0x2fe9e83b77872e6df0f2362a0746b1dec3ce6cdcdc043841f2032488ff0f6c43)], [uint256(0x0a8225dcc20ee5609053358e9de5861333a96375f1e8c605bc0299d6448de4c9), uint256(0x057f6a3f7e6c7a645e527161b2a74877ce0d30ca01723004130f0a83384fbb9b)]);
        vk.gamma = Pairing.G2Point([uint256(0x1e1431858a34cc9012fb369fcab4e7fd844d3fb4d798d885573f3e5768f778bb), uint256(0x13969a60eb557d1e88068f7d35be7472f88a45114f30b61ab983358a4be12aff)], [uint256(0x20f490f9febacd37e6f01d13682d852adb7d2a31882ff5abc22553ab31b446dd), uint256(0x1a5cda3dade35f7a6ff2b67eedce515fac3a8f9923cddcc2bf3f4502f3a35666)]);
        vk.delta = Pairing.G2Point([uint256(0x1e78a445911ba717caca1c210cd556e93e4071670b4402f7697d6a484f60bc39), uint256(0x0891b46b2b8598a78f6ca0cd5b26f9a47e17c8cf38acd9d360b691652ce5ad1d)], [uint256(0x0f8980a872bbbcabe52f1623bf2f6715137c007c294787419c87e63679385b44), uint256(0x1a5af659b2f51a11e5b146324c82e1127d84aef9a3d027c3c24b03e72969b309)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x129b63ed15d42aad42d702790cad5792371414ed140fe9442d32b2fbe43cdc2b), uint256(0x102be628e344b2bbe1f1494cd80c603adda016c9c091138f725cda73e653916d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0d2b8f97863bd90fe8684287adffc545ecfd9e1768666e59ca5166e2107274bc), uint256(0x2c0b6842de678828e19bf65c9b6fea95b5cfc4424e497fcc5d5ba0df3e0b4f41));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x176310d06968b55714160a4e11f4c0396a306d66aaa2a4a8546001d79aa7e2dc), uint256(0x1b76a930c86415277a1500e8e658920c82bf5f6b2a8ab1d2a08b2ac1c1bccae1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0bfcb1660f164d581ba43b3826a36115ee43443889ef4a2f690e09cc6789d34e), uint256(0x0ca1a83cbe316dd602b7a1fd2168cc9f145b5ca621cfcd7a0c2eed34234c0b3a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2a0aceef81b05b764f58138d1b2a6525b8bd3c2e79b1f741d17b2fd157390dfd), uint256(0x1ee8b43a85f930034a2dd77fc1bd3900f1c3dfb3cdc5235195909fd35bc97019));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0b19da78ed8b2c70a5ee31a47e565e524b7a793ad089d3afdb4414bee2b04c43), uint256(0x08c243d0f9abb055d2b5545bf142dfd10b7909d0f75d3bd9eaa905865c5bca46));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0f12106d93b202fdc68de4ba453381f9dc328e2472e07b991e829f5fcddbbe75), uint256(0x29468a525d51459864cbe66427046815e434f015f3d20eb8c0e2d15ee2e006a2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1e7756e7f94197d7fffd2f192181b62655928c090bbf1ab67fba975b61d6ea0e), uint256(0x2747d9c7f9541eb3770e51daaee8fc6269ba023f22309c1cf824d5c541cfc107));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0e53629f4fed477d6e4a045b89cb1ec5a02d5d0680b9b8657990fb43e2baa7ac), uint256(0x1c2ffa90e7a8a0193dd7daff6bfdf036096506ae8500645e0a63f7a44a9b4e16));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x124652bc35e865cecccc4ed058232af16593847ee4768f17720679b58fab5a80), uint256(0x0d87884516561da30cf3bb4a4c6ccb322d8a88e2700d40f18875948a6dd1ebcb));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1cb63e153c6b2ae25bbcceb8eef6bcf72c24cbf70332a9c0f3a0b01e31590614), uint256(0x19e4d0cafd8c0bf9cd456faa2fe67bb7dca0e6f820f29464dccd21dd876871fa));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1c2a6a3ce12d480f0f71246bf7783b0f205f5daffd75ab26f5d6dfcfeab12ab9), uint256(0x0fb0160513df89aac52e4085f7f2f7503eea6766706c24e5db5568f2531ba3d3));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0767dbb5ef4e3cf2eaf3f0df879b65e0437a953c714bb1530aa4bc5fb67c26bc), uint256(0x11b9cec581112bb913bcfef28958ae4124341bdaea1b2070e6fa45d80bdade71));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x112dd59fc205ae15a016afd61be43677115418d839113783ba8bcbc7bf362ca3), uint256(0x23a6c505f9141a50eca8c68b97ae7b19d2547186bf5024b69a67b4bafa8a48d0));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x23d65481e957e6702fb69963eb5f6888ecb8a2d662ae2d2b9a0835172bc373e4), uint256(0x282d32c8277b3b020994a165ae1953d5a912ae77eae47935a002701b708b1ea2));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x282fed92d04c0e518bf8e7d0b327c8ab0b4feabc5be601ee0515288987860063), uint256(0x268affd6082a5de3ed118cd6d2fa5d81280bfa84d99575b27a4600bb7dd415e2));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0700bb8e6336cf9f8d94c3b3957eeed59d6c69e5b66bbdfb76c55f10054bed83), uint256(0x11a73a3597152ae1eb521b9f751114112c1728cf39cf6687f8e023e77f22550a));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x12b87183e3f4bcf1f2f0d45c4c52ba4f33e96a388ce8f1d6577263993c225bdb), uint256(0x2570b98177929bcf6e87b0a11bde5428668b0cfa11b7ccc93c5615d5b91c18f1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2dcc12ad2145d19e4b1f57732fd567b9717f5d2a19981e1f5772f1a3ee254a2e), uint256(0x0f68e6fe3a9e2500cd42ad00075319d5067b936c955071e556f9e643d4065f29));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x20a3d10a8478eec42f67b9ff498511c5294cc073cffe4b1441822e2d9b035690), uint256(0x135a5473f7a5a5abc99c1d4273c1b51490aa03d7024a09444acfcbc95962fe86));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1396a4c4f207aff437a6439c2c3d018574a97576de2acb6d3dea77a43d9f2000), uint256(0x13afc54ffb822af0590e56ed1ae0e3b50ab6d7046d6dff63565ab06a1cd97b91));
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
