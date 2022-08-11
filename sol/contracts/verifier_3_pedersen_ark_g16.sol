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
        vk.alpha = Pairing.G1Point(uint256(0x29b56f2ef8bff4769d2b54bbb7b403e5b8c9715cb65edbd1e1bdff13d3c59504), uint256(0x1e59a0d9045527be2e4e6e56e08747b10f3a622f9bb920777607b50b2a1074f1));
        vk.beta = Pairing.G2Point([uint256(0x1d00b806c3a8451093bd3727af8717d4303afc5312a2609c9055faf3354ff684), uint256(0x1102144f11c876f8632b32925d0b478c28fcf1d5e1416111e24d9671789990cc)], [uint256(0x1f970f3cf03aa949be10fbc88c718cb1d8684faafaa8b2aa59d51833845069a7), uint256(0x03b5a52235117c05bcb2fb1d0b239680bc7523532f70e922f7996b2b0478e107)]);
        vk.gamma = Pairing.G2Point([uint256(0x063fcf137d404f7513078a0ad9b532df34aa68eff8133501cbedf28e220b1549), uint256(0x057aad13e308ea84fcc6ec2415ee7f2e043e1579aa8e4ebfbf8bc9bfedb8f9f7)], [uint256(0x270feba69dcd89a6a6bb6b7f505a226b98c56c8dfdf99eb17d099b3fb80b74bb), uint256(0x0f84199059f7d4d0945fc5689dfdec6370e568ac16b70876e4c78ec938af5299)]);
        vk.delta = Pairing.G2Point([uint256(0x1b563834fd942cb573681f48043444f8f9981138b1c03fece75630261a2f9c42), uint256(0x0795a22dd225ff69d2f5c9b095b650b25b1b414d8438332dfd33aa2779267cce)], [uint256(0x0859e207a23e428f7bb03c3ac050fc7b861d6dc0b20a0a8077e8218c0e1868d9), uint256(0x0af4f60f38d7af66dab61de5e409404cdd5a0619b33e99ddb747bc852d61f660)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x133750a1ba99dae75d5ed3b4c6e919a0dac0702d0a2661897e78ee5eaf55be19), uint256(0x011a7cbb46bdc29690490458df98da67a371eb2983ece7f94e1b017e915b8e1e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x06c07774693564e7c3c4f2b0761c0e4bbdd9ce54eaa35d6e17ce06f0769d92f9), uint256(0x152ea99bbcdf973a686c60423da3402bbeeffdd0d8580898a63241354eda765c));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c6e7d6605a57d4ceec8f12d5ab43cfbdc19dedde1da42a20cbf159678b293b7), uint256(0x0ad75c4dd3f02870882d2cac23e29d9e5695195f68795a87f073293d85918295));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2521e430fd5a724115943492567a961097ac40d000e7c3da450a4d38d198fc7f), uint256(0x2c564e0ea707ae5cfa11d5f985b2dc86f51af5eb8ad4e4d5f06187d68516b850));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x21128663ed25956707157294febc0d94188b7d809df38f85b29f34badc008845), uint256(0x1ccebcd9989a81574ba7388f1dde7a7f6f1f5020f48aee9a0daee0754749b840));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x178c5e6e3352154b3a990b962e3d03057c92db0e1bfa9b4297dd9d82ef1ad2c1), uint256(0x23533a99f7c4d2a1a6edd451e0d477e6ed5483f69d49a2589f38fb7b374c3e7e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0c342e68a89a7b70de6d6fc69f5834ed091f7f99dc5a1fb1bb129e4b6336f644), uint256(0x2cd67069261c5d2837d86b7e83c08f6085d75588fbd0b9e0af99d2dc84424b4f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x227e19f1c8092c9208065c27b2103e7642eeafc2c88a339fe1905b2467023a8b), uint256(0x2c72f45da393e59fcbd9c43e752d03a44c7dcb170e0b7d01deef3785476a462f));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x19b24604522c987fe1134f6307c1bc66a5bf1e8fe8db6d92db155f25b12266b7), uint256(0x1b80a1d62afdd2e4756cbed893c353f6ac93f106dd1aba75dfd1aec00e4460be));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x07ad15cb80aac21bcfac88900e0ccca27bee07814b687023cdf783c29a378665), uint256(0x2ccd1a600a67c6ef195e37a17d3b1ace0c470289a24ed1d81e844ba966f372c8));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2b1ed2750227a942e466c9af9986910cd38b81f121935e04a5d6c43d9b464d90), uint256(0x1f129f074ac9ebffa84223701a0eb8b5bfed6442b40535b21df57c939a25e808));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x113952414dbdbf6ea0731cf9da61542254854b9ca8455a6a0230d20172c2585d), uint256(0x1cb5c59951876ed2b61e35101490e770f5b1e9a354a113aa73f201f10c61e9e7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x014beb538b3e4cfe595673ee85d45a5652c0fe5791c9945d944bef4fccb3c4fe), uint256(0x29082a7978624e80dab77c99210f3af08deb28f8836800b6e92db9234bd53952));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x16696f4cb877c5fad5725d26bb83a19118064513bb9b966b861cdd995dfd3b64), uint256(0x11945fb018fe4db7087fdf27293b4989fa54c07458690fbbc5ce57635c70ebc5));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x08d7893d2bed883539e34780ff1ebaef541591585cc337b32ca924c6c247014f), uint256(0x12a356f14173eee25504f3cf755fd780a49a8f77bf38c16c8e29f4f126732d3d));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x07c34579950dc81b48dd23b039d025bd0f254847968be9c27bfe18a9d5c60a32), uint256(0x1367e789e9cf955770313832ab03febd0da8698db4af7ec27be146e3b88f9f46));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x26bbd094397273c848ec4da0e4ee4886627a7f9dd481547c192e1424499c7cd2), uint256(0x1bb0ec1485ab71c1d80810f6f5bd1e5180dbf95c5ec01f79e282679a0d42feaf));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0935337e7b3dc20a970b7368703bd90633a2f564657fc001754a80090ccc473e), uint256(0x2c39965c6a06f67ebd930e18dd943fdd5fa1d1bd40100af407b3c73834ded1a4));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2ca9e54eb613b0204060d179cb3a727336371c860d16e3bd3a9738ed7fd8aec2), uint256(0x08a2ff304ae9e6174361d0b56a11ad4242dd82c706484c6616552e01d375941b));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x08cab0ddb420fd4444404194e79f4396db7f5778b4c2a46bed95b025a57a6222), uint256(0x2a43a77cf07d7e24d2dd58e15b54894ff5f383244fc52b78291de0c9472cdbf7));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x218716ca80ce3600fabde39727ce234cc31cc54ca63d11c565923e2ab1264ee9), uint256(0x0b2fc5770ac2ea9784e54af9f2be960ed602a763ad5f0a58d7d3287e972de832));
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
