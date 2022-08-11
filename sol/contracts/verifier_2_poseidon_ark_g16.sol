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
        vk.alpha = Pairing.G1Point(uint256(0x2f7d6b4c1fa006fc06a7670e32f12a5a22607ba78e204674bce2f1964c4aebd9), uint256(0x215a9f6276aff43fff05adc3df0c097e1c9d14cb605ab622b73bcc83907d5efc));
        vk.beta = Pairing.G2Point([uint256(0x0fe3a182ed3fe08fd954cc39a6fce816db33172406b1598ebd7be351641876fc), uint256(0x1fa55327a8c5ce78bb22edb3ffff99769a49b158c1f3bc57edc63c9ae798c93d)], [uint256(0x1b5673cfdadf7e420b11a8bfc722d95463823d6365980ce6d37dad97f0c364fb), uint256(0x227ba2fd81bab575538d69e3a9625812661b14ca57c49769afb67d3929020479)]);
        vk.gamma = Pairing.G2Point([uint256(0x2979c79c58d3027d1d677ebf3a53efb4b7330d6a204c9e938bde162ffe5cfd51), uint256(0x1352ec48b2bd2d2b6b3c7bc3c6ee4d28c0da76f1436f6849312add32db1e04b7)], [uint256(0x03b72a37d4b466a65190982bff5aeb90cdae3eea9b2f6d0d2c8c230c9d9f2fd4), uint256(0x099ba66029c7b20142ea3e1a2701c47b878fc4602273192d96a3df6a1e5fdf27)]);
        vk.delta = Pairing.G2Point([uint256(0x180b7a5fce95f88461bc0a55963a5c1a2dc7e72eff2b062e930743ad5e3babd4), uint256(0x1769495c4ff763a1f05e206c1f396b762872b9c6aa0577424120a2e8284eb36f)], [uint256(0x0260f96ff521108adde022db79d3a4cb874296afbddbd698474f348f5f56972d), uint256(0x1fe7f9098d4297f34c9f1395c30b095c28bc0d4498ad5dec3e553f58bd72e197)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0a04091bab22d56e5bcca8c6d83ccdc347d7d034eb023eb09998614c01e90a69), uint256(0x06a99311ed467ba6dd703acd05543065ea42f4dee0580438e7adf2a680a964e9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0db4b8ae75529eb583bf0fffab263de4be7f0396f46b9c2e87d88297faf0d7ca), uint256(0x10d68ef1b12ef8dddc8356b7dd9ec4e385d2faad65fa2f14aa1d94f0281382a9));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0981552de8a431f9583346a57076be77f17eb6acb37c152a2d3272ec17f51cc6), uint256(0x03717a1f6cf3f8e3d5b6a47becb2835dcc4d981f3fdf0fc8fee477ff49539948));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x00bb2c6f004cbad36a9a442b527a896cc443345c98c5563a38eb5f8852c04854), uint256(0x1af212011f1912c858c0a32c3caca3cf8014b5cfcbba48ece1f590608b1a9498));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x193632ac662bb1f4870b804c9d9d8e9af5860b1b1f9f2dc69c9dc90c1edaec5e), uint256(0x1ed5d97e2ea213ad623d0b6c57cd0971e9b7edbbf677adb431f0a88fece3cfdc));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x08d7d0a50413851f43ab13d39856fcd7ebe3ba2093ec871fd68bbef65e524f4b), uint256(0x27b468b2e50ddcfb11a9127c855d956bb7fe3b816d1c2fad47215e3532315e56));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x11d12773ada4e3d55ae7b64d5c280f652ea0c9eb09786ef2c8d1744c80308bbb), uint256(0x1789e2839f0178d5a0838aed488e341b59cf259578f2f2931a8d765018a24224));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1c8ea01a8b8e4f27f6d8381258bddea47e352ab69d3b2590439e8b756ee44689), uint256(0x021e5d75013a487d06c27e615c06137af68ec1b2f63a0d885ab47f720f351bb6));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2bc03dcadd250791694ee4740146695a33721f56323ce195241113879c876fee), uint256(0x2071c7fd77e1b266f51473d8a937ef5e805f389f4df85c222773f2ee057bab99));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x16bc1e932693d56da17d2dcc9ab958a65b60ed8e8a4a1dc7dde0e54d8047c382), uint256(0x0d181c24f96bcbdb69d8a1d69aeffdd6bac54750918e5df0eb5342a74fe9dc16));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2762b8107a52a06516f62be769d178843256a456a2328ca1da4e7100b3209ea8), uint256(0x043d656872e8f85c3f5ea0cfd90db0fc68488823bedb4cc455d6bb3961128763));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1d84d882fa3dec3b6fae486ae199f628690137a8bab0582f4768f6c4194a7ff1), uint256(0x04254e56ac36e4afa5be63c480510052b0d2e0132bf122ad22728578617b2a38));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x06e7984e0d93d4fb2bf0d2f0320ebd718e9b78238593aec4d2c463c8d2ffd3b4), uint256(0x07a7348c99d4260ed37d675663dbcea5d9f93ad20cbc13f6b7c732ad2efed273));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2710323c38f02bf326e494d59ca7abfbe95667e0c3d1e43adffeba5a88ec106a), uint256(0x120d5704fa5453b30aa985d10cc0118be5fe056b47bf4efabab85a761511fc09));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x280939b04bfb4d0ce6a0f1ac3710b1516267b091da0cea3d2fbd35cea5fdb3e3), uint256(0x2d008a9477bf3221bf14ec0f1b69a2a5577e8f72e9c22335d52ee31d391eba8b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0651b08cf8108b465f8d4909c7a69f09a6a3430a5948776073cf9f8500755fe9), uint256(0x0364e5c041cf3f50cccd385c2cf9cf9e36295e81877a2ebeab177ebd39f4faf3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x06ce4022f6967c48afaa419afc91d4e7f078e87cb9f7d34acf562eda649c29b8), uint256(0x2cc6b741374056cdc66a3370b678eac9ef26da7a90b2cb1a67985226607a6916));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x05a3d797ab73fabba39c668dc5a2f5155e85ad8a6b6f831bebd0cbd346f93d54), uint256(0x2b8fbfcba52a381ee1779ddffd5c8936889269d97d4152d52a905bfe38261a48));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1b6bf927f6535a174b773603ecd0848f08be94cd1bf5e72a947e985a4e9d2a08), uint256(0x075e047777b04b5e6a3a5a33eb87d096156307212002af34b7d0ce7d64b47a5d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2765d3ef9227b137a2de78ca6bf394695d74bc3ff8f34f4d6404f4a7c1b95b3e), uint256(0x2e0d178dc8e2b15aacf13ae501cbe7dcc83753bd3851baf96a5a8d9fb6b03221));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2189afc40738bcf807788142b18c61198f140f5edc65c141db10f01b310dc40b), uint256(0x014c3c70d2f2db4b0555fa07c10b2537e97819e2d75f8936fd83ad7a89c05884));
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
