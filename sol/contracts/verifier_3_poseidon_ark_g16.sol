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
        vk.alpha = Pairing.G1Point(uint256(0x1ffba01995bcb3db4e184a65bf9d12c12dc397192f7bb95802abc1108033bb7c), uint256(0x2bd5c2f9fc4bee3ac8af1fe15cf1991e7576a5f162343daef4a9c65060abe61c));
        vk.beta = Pairing.G2Point([uint256(0x09573bfaf1158c35282d1e39aa4e423a59561d907b9cbcf266122e1483c3bae3), uint256(0x091d9679d621c1758557efe9e42d1ef96e9ee1c3d80646e12b85f274b8e84c05)], [uint256(0x08d4ecfd9b059d31d9ef2de48e176c5dc82a41cc4cef486bad72117c29b5706f), uint256(0x0d1734456a6f5d08b267eb93cec7f1438671d62c33db9ed6a70e0e1c0c0f00a8)]);
        vk.gamma = Pairing.G2Point([uint256(0x0f6d81419542f8de731f1e208cd05d8232ec84684faff111110974af9da57a21), uint256(0x1689ed61815a615a3a28a93c84c0a6a50cdf3aeb204bc1d6bb6269dc70b5d5e2)], [uint256(0x2b5fe7f06bda52c69af9ff777e94ea39c9ad4f3cfa13468c2d4d1c0e08c6c170), uint256(0x22b1d94d9bf5fff8ff5d861cbc19100022865f94112af65470949fc58b6eaf60)]);
        vk.delta = Pairing.G2Point([uint256(0x0e5e268d63f3c3822385916be30b2ab3dc06739d61d9f1ea9bed2f3cc3caef7f), uint256(0x0e0d1ead875915f4d43ed13dbf4f83abdc2fbfc837520d4171d21afe1a53c907)], [uint256(0x0c6a591252b1af472c859d68ef9a85aef6a5ab9b074cbd7e229ce2df5b025ffd), uint256(0x24e10e891754ea5da4eb123218d1c3f4a80037a27477c8c60aa5b6888ba1ecc7)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0fe33c58a7b0a5645d81eb0a638682736fe6126b1ecab9e58487aeadad8288cd), uint256(0x1b4f693e38550af54612396b64ee5156dd03325d0e28f2925d45629a6b932cb7));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x10498ffb9a3fb2298eb7fd9dbf02856725b54bc480cdf6be7a74bec275ab7dd8), uint256(0x0de62c98dadcbe7657a3e1de01a257913462b5bb8b7b6064658d4cb9491ca732));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x25c56657acb04930c2edff5bfa54eff0dd2775b0ffe9c25996132d53db85bd35), uint256(0x13a85a76f43e2189fa9ecb893fcf33616f18f5b382bd9e95960a045a16146a9b));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x15855941dce0e0c9e93fad494643e7bf14a8f41eef9a18228c8cf2aece8b1a49), uint256(0x2493125610dfd4a96a69cc93ef7afb98f274061475e469346d59167ba15fdbc2));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0b4bb78e762ff639131d477cdf05c02bd9cb3b5794a7e86e68b914f490a61a85), uint256(0x0edf9740f6a56cbbdc8bc5678808a7678106b0f3c1d8671dd443c9f6b38a9299));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x06a49a805fe3dd29e39bdfa1b65048e5cd914bcb5b2a893a9a49600cc339ca2a), uint256(0x025ece4251534f09296c302f840b0128cac3c075f985d8c869fb95826e2c0212));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0a96bdcf52dbd009b9eac26a9b4e39ee1099051ec1daec349891a31a82903be2), uint256(0x2cbdb9b25357808d77789abddb879627bcd8bb5855ded63a2964baffccb8b315));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2098292c6ec2765954277e6f1d6a3b3a791f17f22e9de1e97ba1497e620bbf54), uint256(0x08dd78f2d13bb744deb132344b29a2bc950ce482352a9a67413c853f7f3ff080));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x25b49824d35a3a7db1e2b6554051f33c21c84c31e6906451a64382a0736ef655), uint256(0x132b033f270269be136ab4f497fd0fa913ba4225cbcbb73379ead354dccf03db));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x217af8ef81943304a8f1778670a4e16dc2bc44f3fdceddcaaf125682a6fb3834), uint256(0x2b284cd754cb750e0eb1feaadb70a2bc4eff373b069e0c704ac2d35682324356));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1e34b227469df4fc1caa4b42e60798e56fe8b80becb15a7d362020123f285f0f), uint256(0x2d5835f0cb233841a451bcfcc93b3fb8cb277d74cbb7619c8d7c10a3bbff29b5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x067fdf7be29f6cec016446839eff32ee10c495b097e089fa89aa86677f01894a), uint256(0x131601f8e2bb53bc048702831cf85b3a23e38608aab27f883f8e302452e62f96));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x3046eecf5adf3836634f3b6f1296472b0552da27b2510b9209efcea105753b24), uint256(0x2eb58713a51b00455761a0b9c6a6f8e71fed8c6e08ff8eea490cd06bad3e73b8));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x06cc4dd1d2d4b5b89e9bc4165f3ca7630020eff20c13defcb3ccbbb45853656c), uint256(0x04eaf8fa6f2ed1f7fd2a81bbea460a35f4e5e0b25549c756df3c9f526bae6373));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x05292b409c3c7bbe9cf2b074850ac1a11bc86266529a724b8b3af44e82b062c2), uint256(0x0bfa59f249e9f28ed6ee67d699c92c983980a8d0cf568bd026cea30f1fa29697));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x241d1388fe150fecf1f81c48454a326526921f607eb086dbd4891da4057f7f0d), uint256(0x1dbf4cbe162ae3a5777a7dbe393d34c60b26d311d4556092739f0df7d58ea236));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x26c610fd0484f07406d68ba90c30a2a45ae9558bfcc49b7b1c3fe64f57b85472), uint256(0x26eb9414764657a6f6b9dfa45955541e501e15975312ade2fc069542978a01a7));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x11ed11affb71e0c772b00d42bd263b14d6d8dc788e1d775fd211f75f8b54c160), uint256(0x0c67e9061f54414c1e1c06ef6826b90f1a6be925c115610aeecca6d531873468));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1dcd6c002bfbf28068f7b26eed62150b19e0d50006817323f61709e1ca90c6ad), uint256(0x2bea207a2f69b4be5340c485ebce61dfa113ff8f556a28705e11c670a288fd53));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1e8737eb870ce01dea2e5509c9ce4b5566148cdc273ad6aa2ce5ad280af7e737), uint256(0x20280102e50b73806e52d320087ab2315f1bcdd4bf9311567d58a4a21be55671));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x23ba050ebfddccdd93bbe8a64e526dee3d5e0ad2196c9956590a32ab8281fd91), uint256(0x1e3b96a463bf10f90d55e73daa73418b45468f09c8f7eb14362676aa4d53033e));
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
