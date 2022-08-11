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
        vk.alpha = Pairing.G1Point(uint256(0x26ef70cc3e0b39549d7abbd596f35aed059909775d81a98fc9968ea6ad186afe), uint256(0x1f9e73bfa039a3667e60a9edd75c9718cd3e046c625ee2f2db7e229bdc067613));
        vk.beta = Pairing.G2Point([uint256(0x046300813f9df120c1bbeb4385f4c5f757bb823b677cb52a02788c6e13de9867), uint256(0x30085f593b05d474aa03184b0f7b4fa8a079c8f65aab6bf8eb1e2480c150b8e6)], [uint256(0x20909d763bf2e785aee692ff4e86a3d3fe964f79d2b1b1a78a4af97f921fe3bf), uint256(0x0aa6d1930d719494d9d345abbe303805928341cd54c8946ebedc80a38099de80)]);
        vk.gamma = Pairing.G2Point([uint256(0x26fc994c7f1991a48c11ecca8fcb6c7e87668fbe4d8a7f15f640c56276580b08), uint256(0x2d3cf1f673c4ecac6a3719857ddedc70859ec868bfb6621a0a2a3711f0fbe18d)], [uint256(0x0cf61c55272a83cef2bee1e419b23f8c69d8fbca828bfc85cfe26e57042ac071), uint256(0x2e02e196507dbd174c42c6ba615502093d7e4b6f12e703f16ef0603cc7aeb529)]);
        vk.delta = Pairing.G2Point([uint256(0x0d2311cc382650b758f4be6d554a5ac79010ddb606fbd72975ad7319a4d61728), uint256(0x26b6ad839efff1bebba059221b98bd19beef6df14c87b0157d231a8c5ac4f964)], [uint256(0x302fb1aca7aeb98f04097ef139e224274643c5df08181255e7abba242415a40b), uint256(0x207d384d0c06a4967298f50f9f132c6ac6623401ae9968b114b07fa71f5a6b46)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24789490c9ed353bfd97ab9c772a6ad910e62db0d0942a627f09bbe7ce54e8f6), uint256(0x1c21133cd048a864ff1b1c2c93b0512916186fb3564c177fa64af350f85dc7d5));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11aec2b2fc52efd3b497cdd5a28b0038d702c00ef859aed23bc3b4ccfa5668aa), uint256(0x11bd00b0c10686d24dc9ceb15e551c2f0a82d2ea6de0bab9d487ff143c267042));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2d14e6c307a5b444866a4e4fc943aa7c8926669fc86c4defb42209832ef6b7e6), uint256(0x1037e7f8eb84ed6d1ecb9dd92c7e90de4e3f64a27e0f4e3e35a5ce8bc4b25284));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1a2cf7ae9a386d8f7d4225b1b174bdaa6423e9b50e479d00e52d6e72109d281c), uint256(0x061a57c0989d791a4d111158ca3c2aa04aeccffc53903b136789baf632f270c0));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x065f05d36e8ef7434ad1df2fb5afa01ff25de5ad87a87bc3d745e1099781d485), uint256(0x1c90ac2a528369e9f8c43ecee9cbf462149ca377162f71f2106662a752d2eaf3));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x14bf499b29c38ad5f83276c7ea79a6695b1fee5fceb015153b49f2b51f2b3095), uint256(0x0bf4c4d3d3d4db8720c4484cea22efad97b9e7ad60208dd00b5efd786452e291));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x02b942ef6449c46d31f2c5fbba334443a8ade7b6bd6ddc26662a135256737a22), uint256(0x17a109e4e216f04d20b2abc3ee4bc1d2847cbc98f40f520fc1e3de56befe94c5));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2de04bc77fe3bfa70c7f3a18852eea13a311558bcbd36db63314d1d75deda65c), uint256(0x29682476703775d966e07140c30d48679953a5192ce616c0d5e0ce91e3de4077));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x125041b09315e17c2201f6a9b3e5b114b39e454d61d6e05849899fad8b34e30e), uint256(0x0b83200d2e19ff50a15ddf227fe4b7c81bead391aaa417e88334f9a236878eed));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x244517c60d84414c789b6904d00982470a85bdb9bb3edf4b0d1be739a1af8b24), uint256(0x101151d4d159e1514abdfa458ac6464a9a902f61d93479f3fb4ed8ce2645353c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x05a81553c29247bfaa984af244286ac89f69b2cedefed12b6e0e3d319bc3adca), uint256(0x0c791d2669328b301f7263cc0becad214a96f18e189725f983b707811742103c));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x23c1825d8fa0edef002c30993658ea813a6bf5226c27e112ae3bb0b652b39027), uint256(0x069fcd61291ba4983bf83f969bbf4daace384715ed5516631478cd22530e0997));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x25dabb2785892f14208046d4af5218c38823c0eb78de1a92f1d68ddcd3ba6ab9), uint256(0x004db49ca16a5025fd524b4c1d1cb5a7f12e576a976151de1d7fc9b0a7267423));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1ad43e6f36738d6256a68cf84fb5cc6d6d58926e5682efc0f3c81a72edc0545d), uint256(0x029441587619eef8cabca68fde43c065939dcc7c70281609ef080992ac907a22));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0acdd3f4397369dc246a67337e36e815137002504bcb78c33fda8266a09ec537), uint256(0x1501b8c4d594e2c9e1b356966a51f4ee0cd7e81477ceafe378ea2b788b63ec11));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x085cde38d8f8f8856a4d4b8dd1f2c26a00a40ffe2bbece2c99ba480b9c76e691), uint256(0x04ac650b8beba60b8148e2306c4648be29bfcbf2b28958548ee152a7cf7f93b7));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x274b36a949ad124ff9c67a1db9f182a8990f67d9bf0c2de11fecd0f10119bc55), uint256(0x197cb7ee533e04745894079c06651344db9b9a02ccbaf205b511361126d38653));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x05301978a71a505d3cc20d5f456c30a59b106a541f23b8d066cc4bfce04e5423), uint256(0x271b8cdac342b98b9009ce0a170e4e01da4ffbefe9ca209ff91fe962ec90a34a));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2ea4f69738373b74dce416024879230be53567e99f18d7bfff4719ccaba10539), uint256(0x188438901135c0884e3ad4b9f5a958fcbd246c10a9c65490b6198957743072de));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1dc50af8b595d6d9ace7236bd82b413857f0177a747d38eee2b676b71ce19ab1), uint256(0x008ce1a01382db896fc6bd0ce31880f11b590a09b9fd605aa49846ad52c2e35f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x254701600ac2cf727150cde2cfa7764c304e50159e307a55224c1711a2fc138f), uint256(0x2886ce54c55c4a0de431976c54a587f5593624822e466dc60296e7a793fcb275));
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
