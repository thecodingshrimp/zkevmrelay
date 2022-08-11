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
        vk.alpha = Pairing.G1Point(uint256(0x2319716cf0a28a4fcbde960fdb06f1131efc99073812f2952b1656c0975aadf2), uint256(0x1ffd0f365e47e96eadfe9fdad1a3e2783255f042105b8438195d45f3cbbbef05));
        vk.beta = Pairing.G2Point([uint256(0x06377c5be0b5799c6c36d3fc7c4c19fc08fd39a38a27387715e5b22ecadb0a7e), uint256(0x0f77e5f8778f25b7f71ac8c0c1e1c06d12c9c2a7910fb53b02f73bb1146e0db1)], [uint256(0x172613a0f5ff6c5e2c7057db2f586222099d998ed9d80031ed87b211cb13e43f), uint256(0x0e0aa94d3102b2f7346091457939a1bf7523dbf147b1dc013b506eb91d1c354b)]);
        vk.gamma = Pairing.G2Point([uint256(0x1b7688369a8183e74c68836ee82214e919a49068c72e144a0f7cbef3473a128b), uint256(0x03d94ac8f6d8144340e265cc14c779e7676cf8280e75fc7a52d74c71a634b325)], [uint256(0x002286de8c6103a09ca3180fd773e962e04dbc90b64b991f32b8a541012e2fdb), uint256(0x2fbd0057ffc73c33c46596d0faf41581d2de9af69e9c2248e6b402576f7eb701)]);
        vk.delta = Pairing.G2Point([uint256(0x0fa7f71257603f6993ac7dbc8358dbf37233c4676f6ca177b4205c27339b7d6c), uint256(0x10f8d1a85303392cdfd572d7aac9e5f415b4cb3faa68609f03d2faa74682f955)], [uint256(0x165064a145b2e4c51937c5c4358b4605d6064e1b079c2d7d954050ff4953ce6b), uint256(0x036bf2a1b2a1f32b82f407f35d8bd18029636a8c27465377d5c8b34a7d7e0cec)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x15b0af32b663f857393651269fd41befc842de905ae9dfe8bddd54b3da6dbcff), uint256(0x0816556a0f27ce736ffc4a754d8991fc9f23f7f29bcbecbabdba0ef484c90434));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1151a9a0ba31068be8e68e41e4e334b0d1884a25135b005a7ada3de9c17aae5e), uint256(0x13d10b27b117adb46ba04a4605515c45220b13f3031ff4c71fc885d082db0f09));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x146dc2f3a1bfcfe9d757d41a1430857c16e107823a2a1bc4581c6f4ece6e534a), uint256(0x23a0c822607525cddabf9d8847a0a5494a52bd3e98a83c7d5822f66878a329af));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0ef9739bf76acfad06c73744bd9f42b5dc22702a6e0bdbccff0cf9df85a63be1), uint256(0x23c68d0d729c3ae4881b66887e6930552e4a17a49306a12b288fb3bee0fbb1de));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x12cc91c5f0184639b92b2e95ba8dcc0ad105a54877279a05053d0066160f29a9), uint256(0x262382c439a0cbbfb6dca15dbd3199b5e79f6202202ff6af7806eb315bb3eafb));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x06d9225d1d97048536957cf1e5db5ee564eb3e35b93bc35c1882352d4c9e3bb2), uint256(0x0e3a12d3b53d3424215d82837e3350c809d4a41a1d7e9bc4d5d5d31f88e7f8c6));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2c51e7eeac808300683782ed75606fd7fdaecfec7630c5136ddea66a1640ee24), uint256(0x1adb6a156f0dc9b1eaf0f5eda3c4ecc34e418ae7d0ec784caf878865882a13a4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x012b7d5e05bd6a7cfdf8e501de81c5d7bef00e2736bc1a18794c8d42ad6fcbbc), uint256(0x2e7f30fd5b78ceb6070fd76ec424cce1adb19a48c3ea15a8f9f9a737c0b970c3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2e9efba6ffca35711fc81d7092f0c5bcdbc4fba3d7bc448ee4195a269d5988b6), uint256(0x2660cb31fc287cb537d1109ef2e628b42dd6eb11adb4737ee86a26dbedfa9a7a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2db9526e5651cbea2df1d08333a4d93673b28bcb597048cd44da9120b2655cac), uint256(0x2c13f7901be94aadca655562cea348ecda92169271c1a5008880ad56d6b629a9));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x01a5773ae2c88f3943295678089a20d8e515e156b0195c3bcd222a0d70638e0b), uint256(0x29ab6d689afd989bc46287fe9662e73a6d3ce068fa9c70397c41716fbe9a720f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0d1c846ea531f6c5119659f9afdc06e2ed06aa85441457df9f8083f9ed1f5660), uint256(0x0ff2d8be60407d5f25057e864484da78539fbeeb80f853d85a9d890ef5230f98));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x195114f1a7f8bc7ebf7eb6c16d3f59b226e020ef4ee072b022838ae8136b8294), uint256(0x2b295236b4a803da9fe00264d8f192f31c0364e1daf67c6f3b65e8877f2b380c));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x24f15d826c33ccd84d124a7cba6d72402e14cd727ceba27fa6013a23dc1cd253), uint256(0x0d4d818d7acb2627e610565b8bcbe70bd227a3f088a755f1f0e23b65a84d8972));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2f2fcb1987f2e8b1bdb5017eaee6e4ae428ecd9f009406c4f2d3cb413c4ef66c), uint256(0x0e48dd797481864c84f7e0070e2163cd7eec8f050ab1907c1d40ede4eedeba8e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0de7460beb848ddd203dcbf6c1b33f4d775b3ed64e31f816305d0999fe3879b3), uint256(0x189b1dabce4c05ec51ba420fb7221e1b0dac13159f22a1aa217345fcdb2dbcf3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x29aaf6cbfe1dd97f0530127adedca254654a8d8048d0d089fb855b27895b103e), uint256(0x11da908b29982a5a318ee28977730800e1ddcb78792dba1efdec72c627fd434e));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x09a0e744dd6833a270403a32e852b67ca4040655b37276d60c745432980c5da1), uint256(0x0cbfd38fcb9bd1c0a271f35f44d4672f6331dfeeff677b88178099ed7c79392c));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1e58e5138ffa1314aa95d18e5d5d4377395d61431bcb44abb350b3f247b3a7fc), uint256(0x18585fad041a0c3c5a67fce22921a0de605470955344e91fd84a50ef4290ac90));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x20649f4bdeaf60c9f82e17e90e90b19f654f1a1ea027bc1111dd53da6278ee74), uint256(0x100647325dd1ff9391bd338ed4d975212b4811dabe690ec49059972f193acb51));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x012b0f65556f4a5cbddb06485770fb935e8fbe7b558b94708ee269e3962fc9d7), uint256(0x2cb7b6381d794cd85b784570d8b2e557442c75b47a8e37bd5e8db0e30f7baeab));
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
