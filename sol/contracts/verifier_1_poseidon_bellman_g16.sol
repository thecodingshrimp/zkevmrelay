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
        vk.alpha = Pairing.G1Point(uint256(0x1d6d753a5a4630a8b95a12230162e083259d893d57b4af36834c316eb897469b), uint256(0x1633aa30f072d291f7440d68fb0c0e7f68051628bd3ef0430aa0d9fb47153630));
        vk.beta = Pairing.G2Point([uint256(0x1d6bd66c535d0b6c2a773340035242a78f0e8093f56244c36e037ef3f63098df), uint256(0x272ad94bc5a9b7a5408341689e1f1515a12670a7c23372df10635e2729bc716a)], [uint256(0x2b510bc9147e6c13c08b271e63a56acbb275374caa02e944dc6ca382b904afec), uint256(0x28ba93cb4175814d919663c8b9eca3cfafe136f92bd759b86c1428bfeb5bffa4)]);
        vk.gamma = Pairing.G2Point([uint256(0x2be440fedc33ff27c13386ca84f4bee8ee3696d051f01dc5b7f2755c7fedb627), uint256(0x033b968a825c8cff50ecfc4347d67daaa95217c2bf0369237e6fbb7c4ddd966e)], [uint256(0x04706fdfee02ec04b0aff9ed15e8247535716671a18274b71e4aee0d8495d249), uint256(0x07dcc188ec16f1a8ae74fee0487c3b8f081181aecb4368e052bb590b6ef245ac)]);
        vk.delta = Pairing.G2Point([uint256(0x093677ae09dfa8ed71dbf8016ccdbc42a0e731930b9ef47fc5aebef4903c67d1), uint256(0x1bbbe98ba556de810f1ac3a64a16cc5175cbcec2baa82dbfcdca16a1a01c3e6f)], [uint256(0x13cc03c6284b3b3af09e7e77ee67fadbcc0032a0bd7ff8ec1d47c7f22594946b), uint256(0x26b10f2fc1f05fc4b9713304f0614762e1d9909ed19d76c29f53ea39e47e9aae)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x116a71672da66777dce2613f07f096f23f0e36c28ceb2a05deb909befb782081), uint256(0x21573f18a2d6d0a59cf63a64193cc40465695e3343ab66c5ec457694c03ff0dd));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2125bdb44dc06d2e9eb60d9b9dfca7f659298290f5a2c860d8c7bd4934f49efb), uint256(0x0642a5849b0460f2649cd017f9dcf43692080c862d41510bed989e9aeb1de89c));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x252882f4b4e2be85f52f2de17c7c64cb5b7ff8f56de85c325737272fd1e982f7), uint256(0x0b0bcb11b4aba81ee3a741ccfdcaeb9dca74683343a55d70193f984106753c7e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x204f3d08f51e4929de3ed1a866cb02ea76e0f41e8d7626727abf7cd59e0d9e7c), uint256(0x00e76fc9a69655778de1d51aa964890509bf34a46f6a65e93bd6281254d5891a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x212a2ef8384248cc72dde9c9e2a8df4595de0f89c951664d26ece6a72789aa9e), uint256(0x0a3af6296a9ddc1d4180dbd4e9f4dc9a004c5dcf2e3f6ad508b63deca9921bbf));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x21d68783d0477d408bffcc5e072568a8439cc77ecd7bb950cd8240b1ce8bc081), uint256(0x189d143a837ae660de8f4670ed1564519b0f6b6c2ff06f0c3657d90a2fb4fff1));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1c1359e0e9081e7a760c09f27e97f94cb6572b33093c22e7b9852830dfa652e7), uint256(0x2a29a9921c352581821e53849b6702ee1522dc1aca61dde649e7b6d2f35f2714));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x076fa91b21a0e4a2bba675712146d648ba94ddb46d5654576b4919ca4318219f), uint256(0x21ac4ccb8cb3d38483eac64997e75f2cffc6df17a8376c49cc3759fa7afdbd16));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x164e7730a1683d51abb1f92b4ae7b374ea1ed02b2ac118a871d9d925ededfd75), uint256(0x160c369bd4bcc54b9890e83cb09960259f7f2fa6a774987a0231fb41af01f305));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x097a149efee427e3b98e95e26abf6ac566ca92e2a7ab14bb5becea7c2281bd0b), uint256(0x257d5a360f29af7380e7fec07dc73a14afee5b469faab098579abb2825c08e4f));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1ad9e9eb8b5f6bf5e07e48bff36e179af56643ea20f3e4376f8186e4c27a7920), uint256(0x0f1cf353a6e6f9aa56bdb106796594b74f5b8a844d7074e95a5f8fc1910d5e80));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x260dca625dc82541c0da248e5c6fff62036b8372bbf281c274d3e78774c4afe1), uint256(0x1d591debc87e54c1f99475cec7f5b9601849ad820277b10919d70ce978fc3c1b));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x11e8fceacd54fe759c23410246fda5cd2b25314a37f9547ad6a82d0cf6ac4942), uint256(0x00846ed0d7c5040dff18a16595159d0d774922d9d2f94980715765a709fd84e8));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x07fd3ceaab02ff08e58fec34776b7671faaf9059316b77bb1d596ea6b7f2f326), uint256(0x1f01b93d86d06f0cf9e5fab6531a45483eb592981caf8dfeeb5bd3f4e1cbd84c));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2968b7b37f57b8c45bb0bea5023fabcc9d9467655a4b9df268b32816943b62ad), uint256(0x0089ab14f1eda5324c4b2a5e1b01d8c491e354bac0b57a94cd438797ea3873ec));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x105669c9603c497f17798b875f5db2807ab393c936362b84b2f2e0bbc93f3214), uint256(0x1177397c4f228712f4067b07200271dbc9833decc735cec03cf1aa6602f62697));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2abb96dd8384e90e47459cff0c28e79cb1ecb9c0242f2b32a525141f13a778dd), uint256(0x2efc8acf45fe62c3dc3ba59c5bff07e85e326ffbb7a796ef28e553ef43ed0804));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x19b64b0e0a8761c27775e11f74b3414c8e18366409317d7f44f29f567c010c53), uint256(0x1c9669fc0f66add74e1ea4031e7e10514fc7b4ef03017609ecc2e07a7139bc73));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x209ec9e99634178646a232f67da9204c9c3c942595f9630ffd276b2613bc9738), uint256(0x2ae0418c8d32c43f78a2723940787f6a7ac3be328b841c67047da4a8bdc548f6));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x20dcc13c76ecab28dd776140b1459c9aa8e0e49f9d09827f9cba6921be9436d4), uint256(0x0ec88336f9a3b3df16af80fe45bd794b94bfcb01e64c16f386cec2aba108ff73));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2a3b34e6b4d144a7105282edfb1bfd17f62205a50e5f98f117d853a386de9886), uint256(0x1c295c0166911745f4384dc09876a4d3f91d059ebb2868f69cdef173964e5e53));
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
