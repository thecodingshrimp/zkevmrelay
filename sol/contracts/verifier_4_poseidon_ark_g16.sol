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
        vk.alpha = Pairing.G1Point(uint256(0x0d281c89fd6f0c4204a3974a9f2dc5841631894d3f7ded8b06d1759123f3d83d), uint256(0x13bd05541feababef8dd7953f0f946e9ae716aac0e34835f745e2b508989f08b));
        vk.beta = Pairing.G2Point([uint256(0x1f5e2edc9a1af37cda486aa18bc736acd8cc64d75ce86c15d80eb842cba40bd4), uint256(0x271b7450e227c1f1a7bbe0b58337c9bf69f83d4bb121bb72c905171f1a55330b)], [uint256(0x10a93e2b964e82b76f1ac5a79c0d62be2ade5aef48badbda134e5c79a6d4815d), uint256(0x037444eb7280512b38be7b9a8092516dee9f19626387188cd9911ef519d6ae7c)]);
        vk.gamma = Pairing.G2Point([uint256(0x29b8dcbf1091b5c3422b70d4b578f4bf8d7708b8c05463733429d9476700cd39), uint256(0x2603bc74a30c395fbf4873b3f973e8201e1bb41a8774ea76084a34f15ba3dae6)], [uint256(0x234a97b865b19437699d8664095ddd256cf5d3def26094e839c9d632afbc6059), uint256(0x0c62b1354939b80cf8be280b5d7bf0a82b9c9b02968176c086990642ff1d1fd0)]);
        vk.delta = Pairing.G2Point([uint256(0x0031975e8949647403afbc3cdcc17569d40e10d6a673a69b0fd3b389abfa1d56), uint256(0x12ecfc62456692cc4a7b1059e40f5b7b4e447d26df6d9ebb842f262ad6039472)], [uint256(0x1fa8515a2fa1fa5ba538455a431ddeb60984a79504d48b989d07754714d0d899), uint256(0x28332c662dbf4820a804e53182763a772581df9747e4fd1768cd992b73b44e5a)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x258d90ea8357f28cfa1b9f4a466d65e218ee6a39a23f7c2a60a50ccfb985a60b), uint256(0x13e0183c5e42b5a1ebeee0a4cb316aede1fb0aad6ff27ff31609d66aa5ba1230));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x16ba5e37988d34e41ad72dbdfd30566037067dccf9c72afea5a20b1c9185133e), uint256(0x15d25984987ec709311b8d2c274c9e84c12db5bc00bfd484787799a0d759bc64));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a474da9ca283b4999579c799c937339eae9640d15d940c7d93ce3ebf097794f), uint256(0x1ff78b0a130ad97a0adf710df07286532fc565c9480f870c2068aecb605ce732));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1048e21e3b5957c6272f2a6d94dac94d234497de22fa13e971b77840a2f888cb), uint256(0x1b980b06b5f94ffbf20ec94f65a3a2346163325aab37476dd92cf8ebfe46182a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x00372e9592ee93923ac20d77248f00ffb7a990e9f2a0ea16f9d0bcf838ea5706), uint256(0x189103fc3c081df87f956ed2af3d7260a0ecb408d78a161d464e33621e3abfcc));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x161f2b9fdb43552983149a4f8366575a37d392f52f87931ea72905fe16520862), uint256(0x025627a7ae79cd1624cd42b9b429b102612c3f1999700819225fe3b93190a900));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2cd4fdee5176d84281c12b3f68f183f7df9ee4c43bd9df22ea8da6462d63d4c0), uint256(0x110904d4c195a6b327b6f5dc01eaf2612aa3e468fb5af14902f0221217351efb));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x174cd18ac6e37945fc780d1a65c01d3669b929ba1e8c8fa87408286168e2d542), uint256(0x07a339a17da6d45df1e2a519c8b0ff04c6b0296ab29da7f943f0d9f63fc0b621));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2d8037dce6b79cf30bcc377d0d4181575622d20e8fc20dd7ae87c95adaccfd91), uint256(0x0a67e9a3f8bac0924387451f0750fa2dec262472a010a9d4e417a9e2e9304d13));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x21217329710c13693ad3a3d79e572fb017614df64247f1e9ab1ff74e6fb0a1de), uint256(0x2139316a5d95428c3a5fab52114a58763ff872ff04130d62cca6ad531c1d17b1));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x039b2ef5097deab990f8928f8965831bd4021736d48171e8428c851c491d925b), uint256(0x00f319924293c6565cd2e47633fe4f859f1efaa40adda66cc5455ee424c7b1f8));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x089670e662c88470174588655f77007e56c7dfc2d09b23d04772a0c6895ea05d), uint256(0x249a106bc29525ed010aa64995faaac0f32e6e5b8e38d1285a05c05ac1323793));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1b834742d6c938ac159852b76013cfc16d9cd91fc2459bdb83b37454ea2f46fe), uint256(0x2b342161c42ce8e6ad8ed9217a59ab136d87b78923307c958b21812f83298f5e));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x040bedb88c389ace16329d938dced9f7269f09ba71ee6fb93e9a94f3754fbd8d), uint256(0x00985dcb3f7ad292cb7f09842781c94b41820b6b2a33d78974ebc5f1451d3a42));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x03b0cb3dac8c3ff812d6e959f2a5155a59875dba36e7fe6e60941d3e2e1db663), uint256(0x24dc305abe2bfbf709c948f3a91c4f2e675b5f14b0e6e5040856f4fd6a31cb86));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2b8e988d229a3156d3f502ee96225d187455e7ec8fdfdd9279a1a95b5cb361f6), uint256(0x141aa766e1b877fe53dcaa00dfb1895b9396bd7d7b27062fc977da292f20e974));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x202be3051ff663e2daff05a552f55786b94b0641c68b1cd0bf3b5e31033e364c), uint256(0x1bf8533fd82d9f332c5dcb0c76170d18ec57e228f574e857544e760a7f6ad9cd));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x22438e52ec37720ea60787821fcf98fd2c5a225cd626edfe6b46445958c9a6f2), uint256(0x16e734f28367e98da54c721e0fef8b1142135a444ea96ccfffa32fb807fe4491));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x273f3f3431a27ba937a80b25330c628886a898449ea6d5a25e50b9b96a27bcaa), uint256(0x29d04e3b0e90ed159b2195d9155a00d263a2383ec371942faa5083edac5ea9e9));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2de894e90bd0f5359fde8c4a0994ae1d4eeecab107e20bc9ce5c246b324c3374), uint256(0x2044c7bb929ee4696c1b307ecdc2b01eed06bdabc48418f2c2dbac1554b32896));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2a95b27869e9344a3835763016b2e1eb8e576b4291104508e22c9085eaa1b404), uint256(0x27174a8d587427ea01a10523e69f589aaeb6abb564629045d6e41985b38158d2));
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
