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
        vk.alpha = Pairing.G1Point(uint256(0x143f2cee8e7e5dd093ff7604b8938f0f7ee61cc4dc39b922fcafb190c9ff6bb4), uint256(0x23576ff382b0d457fb95dab295f2add16655a7e0308ac36fd1041e6b065ebf0b));
        vk.beta = Pairing.G2Point([uint256(0x25ac3e0308603a23deaa15bee87b8afea012941f75a2f0fe11f7ef1abe04b40e), uint256(0x2ed3d62ad12328609aa000b5e3eba26b665ae34c163e8ee8a7b6ea475942253b)], [uint256(0x19f905651f8fca48fb88a07b6b85c65fe74869ece94aace1c6837ce571263a15), uint256(0x1a46fb782b25270d3c926d673113a344ca3b4dc3c0eab26f863412ec9e26265a)]);
        vk.gamma = Pairing.G2Point([uint256(0x1d8887daad06f18ec9af0cd25e90dbd94838b250ad9c415a5ad75c7de7342afd), uint256(0x15dd64043c2add4589717d81fc9786905974b148abc27fb56b2cfead574c917e)], [uint256(0x0cfe85b591e1cb89a7935936204aa0c93be6a206dbf7e48100bdf8c39448a04d), uint256(0x19d3befb3f424ab1716ba96748972f61586db205491f670dc5613413a5b96489)]);
        vk.delta = Pairing.G2Point([uint256(0x19473d4767bd9b65f35c76791cfceee1850ef7302b59bb4be958dfcaa3b36d3a), uint256(0x27f9f904f7b7db49164e3d1336b4b333fad3516ab59e79d8bc60c092c32aed0e)], [uint256(0x1fb6dc470abbf0b7ebd247a4c4c1af19f969200fc68acfbcbfe656b91d26cbd6), uint256(0x2a660084ec3b829d1418388b021053f536c9888b1d58294d8f3b79cc973d7aa2)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2f75c34c06cd155d274fdf83189f7344660dfa16838c45643f5180d6a4aa6539), uint256(0x25d016b77910d93eb93da174d3dde2ec7a7dfe51e2b5c9de1cbbb8096e40f27a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x10e883e0d41e81c206633bd2299c1c45b52d9bc27a5a2fa48261aafd79c28e21), uint256(0x14ad033d224e1699b469b1bd2eb3c2aefdebe1fb1de677deec8fe0bb19ad0a19));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0519c639466255accca4328f50c5cf15388525769f89d927500dd9546b0209b1), uint256(0x00cafe39bea369b5052f7bbf9d728f4886229a3442909b5f72811520f0e4923d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x13afaddeb2b81d1b06a051641367f421c10e2a03f8335082f097f4edeeae6e25), uint256(0x1bfb2ef5f62aa087282290721adb91bf47fd5995e74beaf034ba3c0e66ae6b79));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x27bbfce5bbc5109597f3b15c81d8f1a4ada11e25ef503891ffac6515650cf104), uint256(0x2f90178996e5ebb0e5c645783b416854f5a2a0bb16499d9375c289886ef8a5c2));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x054479114eb6c18f6f9bccf138fa62d7a5d876c613a99daf249b842c7bb8578c), uint256(0x12bb2ea6cb37a198ef1aef327affcc8f328fd4667eaa4c9b42272889b8d0274c));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x217c7f424d8d73c8f59bdc3b126ed409f35fdc482188f8ec567da92f81604b3d), uint256(0x180e8d6d27831d8c615f194bf8b68626a91017b89d9ec2672135b86e2f24d6df));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1815920e0a4ff06889d10521c6cf50ad5d596969bef9b57cfe24b979494ddef0), uint256(0x01210ea1530f34c8d3101e69db2d412b44ad4fad944a967fd552c71ed09e6a40));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x17c59304a2c7b035148fca701a273d428bb003c81ec68b20c3e4c39964ce97fb), uint256(0x14b9c72dbbda20861581ee69aa87dd35456a9990c85002371101b571527ee960));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x27575ba22ce404bae8602a0a4ab861a345f47f4cd7a43dd15165992185554927), uint256(0x1dc78a81d30e71a53de003da980f6fe9a5537bf3912bca81b95c3a86860460cc));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2091a6579186bb4cbed79c6fcb69ed0105b1150df663e65abf2369d12bb01429), uint256(0x036d69ad6d0bf04360da124d3d1beedf616622783ed4d6457f4b9c12b2310c7a));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2029c7b1ad87cfeee89363c0b4217cfd1e0a23c8c21f3bf12c225e59bfda8868), uint256(0x1f949937dc336abf30a69e9bfdb6d6a44b3c7fca6b1d0d0d406027a64a62ccb6));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0e34f316cbb7aa8cf8b0d54a895b8aa60b0491db2425b3d727a6479844767466), uint256(0x17c9028ccc0bf2ffd70625cff34a63c8aa669659e9a3412885219d138272774f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x06cb7e5e46b595c0c1a6cf3adbbab220ea82b547c1900ff29ae25c97a371c1cf), uint256(0x12c60f91d6b0e4be70695bae03e91ce236c19bdd26293bbd1c87aea219d7dd5b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0335022739eb6704027182b958d0b45af2be7f6a11d40853accba26e10c43c63), uint256(0x06c0bfea53e6c2382fa6ee749e8479de48d59d518dfb3aa8d7caa1987e0d0f3b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1bc65ad443d2d3d5dcfc1bcfbdb182c4e97a7794f6e215174fbf39fe3d9ac947), uint256(0x008d1440a1e4833873ad90d4fb42db446a68018146e316ed175f7138da9ef064));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2f1ab464e606b1c340b9e71df991a79945326a132bd3ac405de336d02acbb0f8), uint256(0x2415ef12ddefa590e29b7eef0319c873e3b18db045deddbce8d49d99538f5bb4));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0e3c36707bf40ed466d8f439202d2701beae699cac176478da241e5b658328f1), uint256(0x0b12f93d128127bcfb2f270fd21f238be849c10a8ea7dad6de5f0906d77c9387));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x094ee4bd1425f65e2f3ed28b8bcbdd30e2a24236d012c1a3864e1fec75096375), uint256(0x157e505dbacfff719cd173ac06feb486e2477ab27516cbb907f17557a691ae1f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x17554baa96e9c196ba640e4dd11776811dd11fe359233255c6c4eea2d5cf56aa), uint256(0x1fc19239da2458ac47e9ec0ff9dc403d3e818373d318d819996c37aef74f81d4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x06420344b2862b2322a412a8a83c40c6e34056805a16885aa2620f8486d88612), uint256(0x119357144660a6c0631d8a06dde0b1677023bb492f5a20e5f36d25cee99741fe));
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
