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
        vk.alpha = Pairing.G1Point(uint256(0x10d70571c246005d294d344ce15d3173c7d2dd91ecf79dee4ad37c49bd6bea87), uint256(0x18881d8f11869cdcc4b3b2dbe8d0a74eb07d4563db262e71e7d41960c59be482));
        vk.beta = Pairing.G2Point([uint256(0x2d059f62fbabe59f76a8e69c655c841624c59860c7cafbb693cdeeab0530c6e2), uint256(0x2940ffa7bff03b422de40e64502ba9e009c9c561fdb210f79f6756d0fca0c0ef)], [uint256(0x1609bdcd75f96cd6e8de65ec5d72be4c176f5512afb9277c45816dc48f4dac56), uint256(0x07cfa3e5768e460863d4e250b68086ad5a02903eb533a34a9e45cd28a3971300)]);
        vk.gamma = Pairing.G2Point([uint256(0x2777cb0e154f5805ede33b966af2fe9dd949d5d88ccedb53293ceef80704be5f), uint256(0x11212b77b189a6b246887308dbdbf5924df0849146f754fc530f6bca4c161a1a)], [uint256(0x13c5a0d1f2f2d185591fdb17d69eb8eb623ed237d1047486521b1bfb35cc6931), uint256(0x0379fc99e2fd83ff45b7892c13dc5d4beb4191598e8af3cbe7aa89769701b71f)]);
        vk.delta = Pairing.G2Point([uint256(0x1ad2fbfe5fd2eaeac09b3f6ff89b7b3c6c0d4186b2d246d46a9b72a9c22b891b), uint256(0x1adf8d9b0fc49cf157410d704a18662821916c7bc2f83244a8da141b8b4aba49)], [uint256(0x0c753ab09f94cf72d1f36c19af03a38000614c303e041fcb9ed49179df766ee4), uint256(0x040a7ef4a5934881e17d0f2f542df4a3a6c17279215cff891c480eb1dc349985)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x05e370867adeeab45a3a36820e52b334751b4b2ae3132636f62b9866878e0807), uint256(0x04b4c6b4be5ae44fd475600faf9eac2c2f7a061d944e1481d22e929294223883));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11f393d5c992ef9555afe23ce8a5bb0de55b3a8df631b5349f2a0fe1a230f6c4), uint256(0x22af65ff571debe1591c9bc0ddec8a8add72abfcdab556a994d1b0b514c3ee12));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x16d8e31433f1b3f99bbdeb62e039df19ad5cd1d5432a9d58c29404f51e5106a4), uint256(0x1e0ff5d0fc0a8870349e6c86e85d0b83934f20ea6bd4d04b4728e40dea4d5508));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0978a91d4719a19fedd64fcb4648e9053239880c30bffe39e161d7435ac8d2bb), uint256(0x1e793b44e00bcecdd53e7186eb3f842b96404d404f91366dd308c5105d806c0b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x07c21764af7aea29b10c70eabf50677183c7cd48f6571c1aa288bed1f0f32661), uint256(0x269096016c095731780d7e03e394eac44810fd06f54c55368d7ac3640a83ad0b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13a892b65a0f3ca3a5dbdf1639ef089fbac0acc1215972c1819ac5fe1fd08b68), uint256(0x2d1aa6c4d2a3e043247e74ef46b838ef226a5b5a61aa2fcddaa1bea897d5e117));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1b11cd8be840775259589132575775ac6b6aa7d063382fb4d39c85034b62702d), uint256(0x1d034225ac91029b283027f016cf220f2acd28cf0400f1743c4f25131fed33bf));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1db7f5992c12ef31ef99b4a1d581c010a149497d8deb77546b2e8454df104331), uint256(0x29349c3eb7154c84dfce7066c1c8edccf758f24ba86c50c9d80134c1f0740271));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0862085f63da0c258b1935e22127074e5eff92bd153e4d8788c28c065f137a22), uint256(0x16e1f014f6f7990979037ffc2dec03f5e534f1cb75e76281043d65f10bcf08b1));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x13905df410851fc83b2731fb753b476689861347704831745fdba64b1d8a87ef), uint256(0x0e10a046ab8614729d936472121123d218487b15b21f88d82646c7e77e31cdce));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x09c320c17ac08c2f9fed5706b270ecb2440aa89ca18b32ec94873a3a95f84e3c), uint256(0x0f0a4781e84187c081cccffd6bd672720784c3a1e9cd7dd729d1e4a529d64027));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x185f0c67ba4c591b98525424c7b13942c4e4f9cd89015deda7b0f3582366c967), uint256(0x0e0dc073c13309955139c2cfde32da686a79c745c552f4aaeda0fe152ca19c1d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x167526b97023a2232b6ef04b1e2ed1c1b1387876acd3780c4d07e73fdd1e2dbe), uint256(0x01af34593b909bf54511957d0e632dd029192ed2720ef9b1faad11ca48a9a553));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1caee654e0ee1c0a455db6feeb1269771b28994e0edb28571c7bde2c09a022cb), uint256(0x19fbaa5198e957b4b782797705761eeb6235e9bf7e9c2f87ae09a86b92298a88));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x263a5d0505db9e311c9faa6d21260bc5bc5c581ca2cbe14c64b535e1f0f48c5d), uint256(0x0c5f9a1dbd295abae9192eb68447e03d164313e775eab610795ddc3a1d9bdda4));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x19733b52cbfa22598ff039912b3ca84d6da2e01339a310ae9d8a5c8c75cb1d50), uint256(0x0e8fd8fd9a2228e301135b8a065b459771ba38e67723d22c01551b7cd9992a65));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2b4f0673f6ef9d5547510fe6b9c75571652c0e2547fe856d0277abb765197c36), uint256(0x192eca6f892b1d11f4aa9dc6ef3f05bf8407574de47e5cc79aee7b6cb9fe96d1));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x20a1365505b858459b88e779f093cc7caa8ecd56360f6abe693354420aa7cdf6), uint256(0x01dd768f77a71cadb68b5ff1ef6d648ad3bdba6d4eb5ee0c5ff21723af3b72ab));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0ed93e0d3abfdaff41e1b5442b0266705dfdf09b33aa0f796a0b8a00c4a20c90), uint256(0x2e9b026f0a04f3414a57d8792e2aa15441f97e328c5d0b5c7ebe8f7e6ff7b875));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x05d24a86d93a63a55e3e725c464cdf2d1b208b2661266d84a997776a3ee2c27c), uint256(0x05a90cd2c08a6c29938607cb02b97e66c65318162f72c4f8bddeb1bef0043375));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x107d3c8c9ac227d1bd06cf6d58fef555fe29b6e7d833df0180d413539b5b9a13), uint256(0x01c5dca4105e5689d688e124f2707f7a2af5ccbac63afcc3ce15af21af6ac6cc));
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
