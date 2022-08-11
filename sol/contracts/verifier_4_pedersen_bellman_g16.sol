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
        vk.alpha = Pairing.G1Point(uint256(0x12b5ad01744b4f4d9caad40c49500f7248d211d33ab07239e62b205fe3eb9f3e), uint256(0x0b03e85c6239cade0317599fe173199b7adbdd4040a7b6aeae51250ae63052c7));
        vk.beta = Pairing.G2Point([uint256(0x0e1f7dd787e79b4bcdb7ae7e2579f344e99fe898b17a48cf19075ebd523e08da), uint256(0x0b291c65069c5cee8d881644f0e13c0f61d7c68691a530c7fc5dfcbf7f197737)], [uint256(0x038f6a7f57333795e7072b2eb3512ab8a05dea4d29f2b50cc538b4fa8f1f82a4), uint256(0x2d10a84fbe779b96ba84a75686bc66ba715928b07b30434408e1df155324bfba)]);
        vk.gamma = Pairing.G2Point([uint256(0x2e7dd953286b132fb0e5bbd1bec1b2ca659eebf62ba4db720e6c44f2d55d4f95), uint256(0x1a1c15e04b04ab0d22e1b67fc57854447df7317666dea2abe02c9979f4dfb25c)], [uint256(0x15029351d6c156f73fe4185e6af9550a12d4eb0aa27063057203031f1bd669d8), uint256(0x0c266fe9fff0ec3d69a24b8c594b00d560769e044b8cfb568f4d7a88d871a51c)]);
        vk.delta = Pairing.G2Point([uint256(0x011984ad985baf776e281cbaaefc02bf715d0af9c2b2981197c260b694a1a50d), uint256(0x024ad3cc2ded15e4984febb46d1112cd82f36f67b275df96df0dfdfb8ba7fe9f)], [uint256(0x02e6cadd2af49a401780581c590e2b913de6e4e46dc98611cd2a0b7c0b34643f), uint256(0x2101a5d8f671036b39136ac4f3ef67583eb9d01a27a1a2b482fa7c3c161b5fae)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1dbcb18b3ec820fad962ae2a6e3d318f9947ee9ccaa28a0badf68e818cbb83ee), uint256(0x03e4ddf56da96b55f4e97b54981128d220aea92d6375d6b6e1eabf560e76f4dd));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x19d243fb93d10f85d6c4b574a5f62010f74882d87f73a181c3f084e55110e0bb), uint256(0x0368036f5709f6a103cb80c577fed502c83501ee3cf64a2ec2e3e8ff82d2ec91));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2a68dbdd5ba65b939fb3803822901c2b7af9e0bbddb8cd4203d465fc494ea68a), uint256(0x1340715645362d50ce2d62bad4b0b35137fc557313241732158187c61466a00f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0a0764d6fad42026acb4ecaa09fedcf928c4be872fadbaeeee4d256781be639d), uint256(0x2bfa5724bd578c9e4afbe5903923d4438abfa3597bb0c12d5265b3fc650e3f97));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1123ab5a641c039e92f579f9cfcac2a084129bce29bf2ab3ea0707f3ba9a7557), uint256(0x1a47a838e76c965e9c3797da574fd45427d8d0f076e03130101f13f4c6cd1b2c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2628bc29517d1834a0df06e1a0b8a73046e5d840a2fee48f1e6f0c78d9dee14b), uint256(0x1266ff4a459aef285900f0b2edf948adf90abb92a60904ca13cc8f2bf78586d9));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x07a04611a685dc364a49956c8aa3f15927c6f17db1ca25da8e41fdb5d0338395), uint256(0x0617c6246f3be3ce8acc82051564a9d340d77e848ad75c2807361d1446245491));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x07ab164abc9c742983c5d276416c4343db50ad24dafdb4b275a8e38fc6083568), uint256(0x22e5280d53498cdaf23f14b5a6053aab23d64738f2a238a4fb3129a77c668933));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x061a36ebb6a50f5ba95f8b9b846de29d10a2f54f5b7e0cbafc3527f5fba82a3d), uint256(0x010330fd2f2dedffda0faabbf3448458367a28d7d29db27d39cf140669a87a5a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1e554d0c4f9c4ce3e180db1e36c8fc6c5d03e0f32ee074fdc6df0067b0a9ef10), uint256(0x15bf3a32bf1e65bb2bad30858e2cfb002b5e20cba680f4c9d8c21d73e84b34e6));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0ee120258adb56709d2e9ebfdf6b5d917f95ba86d4228ab2621b6a57783d8492), uint256(0x1c50a1da23f8efc39033645df05f0805f018e0c4ce115ec599b511cf8e6afdc5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x20072ae2e6a85a30652e9c50e3714d0dc09623f62b817a03c005eae62a63734f), uint256(0x05acd89ea2a910728621f3e3d602372a576b1eb824dae28f2f2499b7173d1a8d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x239224acba02f278b1fff0ba86f7de875f8083aafdccf35be1bc924c5cb26cd4), uint256(0x13ac32a5060b4ad06ded5ee101c7098911bac3066881273a421eb5ec9af86ddf));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x107767d2aaaea3c04bf3a24f4f06db292e10fb67f5f812938dea87a56b3bd1c4), uint256(0x0a6fec5722a6accbab244d27d9179434d2f2814949a851558ac2b6ccf59f49ee));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x25c451e4d7dd8f2279065fa50f50668a1e7ad29c1900c011e46a19e23e053d67), uint256(0x01fb5a2feda83d1a90b6f32ab1ff5aa3a006c4adcbd518863fd50dc0bdac6661));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2ecf9eadd1106eb347d372ab16ea05ea5e46bfab99d815746889a22505c2623b), uint256(0x2b11d007f8cc3b8494ed2ce0e1a9ee988e988429bbe90ae77cfc04f4a7eb7b97));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x00c4d25ae4bc49cd5e9b3201fbd2c6479cbc951386c45e7a930086b24c7bfa4d), uint256(0x1af5f0f7566c2dee155f6947b2d0104269b764f425ec955e50479fa6617fe7c2));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x117535a33dbac0a48414f9b4fa3f533f35b84c861aa30d70087076c0ce1c93c1), uint256(0x20e2f84d15c92153f3135c8cba7fb2f757bc42f690cf148a5090ca499b93d446));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x15c51781e3905430b253d4f4aa0cd85429ac8f1450d53ac03a52b908da4bc20a), uint256(0x0482fa51d3e142a57b96f67cd8143f35d70581c33c94ee4ebd237c2db0e80c73));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2e1b0cdc61145c8db994f1b1235dcba8c0442a8e9b4ed7cf5079940bacd0e1da), uint256(0x1231ff574c1248b00d4311fb69091089a0bb3bf1ff062952874e02217bd748a4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2959bbcfe50cd3837a3da24e072b14f747e66a0996fdb3d1956647c7aed1ca19), uint256(0x23c183e827604991ae5d561b8513b623eaef8ccd4a7cd23a293aa470dc6dca5b));
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
