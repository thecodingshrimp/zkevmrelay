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
        vk.alpha = Pairing.G1Point(uint256(0x1c88db9fc9b15b4e8984de62be4ba9cc70536d4604743733530350a508e216bf), uint256(0x25d1c1ebaab59fc5642f51964426f12f3e4dc1c075dffec7a91413c9c6406e55));
        vk.beta = Pairing.G2Point([uint256(0x271c38565c27f4573239af59f79bf49ded40e1a8f4a07ec00a16143c944a9ed7), uint256(0x09d73ee01e660c46351307307bd7e368b632698f580cb47a2d3a217f7df6c005)], [uint256(0x1277ff685461613c12868f733c694189cd81c434a2fbbb416689adaca48bf310), uint256(0x1f926c69dac583a883c4bbef40177380d88f6d40cc2c0aaf54215a925f0754d2)]);
        vk.gamma = Pairing.G2Point([uint256(0x147e406effa732348b4436e7a1529c3b35be2972b30515efdc72e81a57ecb7b6), uint256(0x08f21598dc3f059b5a6f4552a5c87ba601df1748f47b9997fe5ce0030fa46c61)], [uint256(0x08160c1b86c1f3750bacf816746d4bf202cd1f99e337d0f03de49ea7b2476b36), uint256(0x0d33f4611e01a811beed091798ea742faf8edc7257f26f1100d894125a293865)]);
        vk.delta = Pairing.G2Point([uint256(0x14e64f1f960a76df2466bce6926974da6035126e386e7d57d8441628def2f812), uint256(0x07730c77406a4152c3cf318d4ed9c9520f0316877bef6b6cec14889f98578a50)], [uint256(0x2e3f7dda332a3aeb8d2f2189cc2fdea151b106b828b93722460ecff4b77f61c9), uint256(0x02574ca447fbf10155da41e278728b9b9504983f4628c5b724eaa4943611b7df)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x205e91bec99a4819928d5dc4586fe86ad97096e280b377d119e2a0ce7b755161), uint256(0x07b6258fa5f3b29d2868c4a90604080874946980fa0df705ab96d0e64bba943d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1213bcc082f74ef892cf63e8d7983478a97a75dc1a22824e23d064f4eed85de0), uint256(0x1e50549e65db692652b8f82f207725b61225bcd219dfb26bbfa0e8fca9884cd6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x14ba68a3974e57419dd4bcf91ed11d7399167ea56a4ba1d25007dea5d4683b8e), uint256(0x0e3d9eb7e37b6e5d55725ae562f990e8a31c499e5cc577acc6ada624e42d406a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0fddce048dae6fae00abd2084b4bb6657b5e814f0caec930ba8b99c26b5f2c6f), uint256(0x27e7187d6a0a0047d6776c8cad2e02092133f5682b84d6c5e79ad616ab1197d6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0339c201559eb3232337135f73d84851ce60c88b1c460b7d615ff760bc827b7c), uint256(0x297890bf28348ec8888e890c35d6a1bcdb033262bf2bc7f1bd48943ca86e8a1a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1745269f1c1813c6e4098b840bc0b81b6665d2878c8f4b514cebdc432910b265), uint256(0x175b82ff20486b517a7e88674117d583556725b23dd35a93163e64898286f2ee));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0fb5591e7df6ab80f90430d6b614e40a9c9cce61c610e52bc6a0f99b4fc4d424), uint256(0x027b8b4d114515a0bf9caf39169ab6aab2add7bffbe73ff3076ccea8464746c2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0e37eae06b7096e56760ab8ccb7fa0bb31377f9891a6a826d323ad65541d2ada), uint256(0x196ef9d4fe0e012660f7088b895a1d244c4208a43777b80138f671df103f79da));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x08b14c5cc453bfe68fafb0b2c1770de35d37a5c4f46f52ae95d5f265c81f61c6), uint256(0x07a4ed7a744b561827944eb713acbf17ce0fd9f5f72bb874cfbcf8343e6fb52d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2f1b46b3e71c589c507d850f5f720417f54620d655a036647c9d6053ff1f1049), uint256(0x0fa33989d006707305eeb2b320b7acf79d4ba3f48b549dd37d8bf33dc600a6c4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2a6b4c556fbca09b935196bb37db2fd8eb363a163aae05d559e263e031bb9e02), uint256(0x0470e678d3baf337f0411e540d523dab436c40bf6c9247e3b3aae9e72ebf1802));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0530112fe136760436d7cb66f0c9e7ff19fb56d4301176bba260acb3ebfc4119), uint256(0x1c1d664105434ed94cb65412e6013d0736368c65a5c5c7f1438bd61e71f0ab89));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2a0126bf021eb8bc839da4031882dad91e9f93fe112afc75eb34839a147d7933), uint256(0x11e85dfaaa92c27c3f3a12bb2651ffadf38df1c77ba3b46dee58a86be442a05d));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x03606a6ca2ee8e96c9940bdc8be46ffa68d6dff19415cdc2336069c30d96198a), uint256(0x1c0f48c298a5c0d5209ed6cee8307a2969023505b3ecc65d5eb777d232716b22));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1ce262ed6108d5cd39e21e20550c4d994a649c94fecf943cfd6e5b127016de04), uint256(0x1935e0c74de44d6999d38f323b4010219cc47719d56d5a2faaaad2951db4fc46));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0455f7929785decd53f7bd0d8ad2be508537a5770d2e8f4463eccd6a75d14e83), uint256(0x28af137fd4efa2844014aa020a43e14588a7891d06f025ad82c5b305cc07c6c0));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11d2a4e1b4995e616990492b8934d98f7b6ae17f0fd03cb1991a2cf223073c92), uint256(0x278803a4da43b1ee70e8e2953a5b23e9b142c972920be56e8a8c8ced05ad20bc));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x13110cc87cf527f09226aa9c5d25d6287ceb04666bcc7b1ca2fcfa640472acea), uint256(0x218ed761dc86f516df671f822b15c71d288d5967684df465e0a627118db866a1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0b4145127400954035987e93abfec855937d739a7a6e3bbfb2655bad4143baa8), uint256(0x00f54e7e3a24514ca48b6db1002f90a9d4b41c4ec3f7f70b8f04d55e6d26a791));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x07a572c955c447d1955a8407fc4f35bed6f9ca322e6516709e71b0a87b5b1e26), uint256(0x18c6cded0bc895a06b0eb1484b2d42887dc46dc1d3b8ff13e7e4484fee9fa332));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1559697a93e631dd4389da01f2f08b64334e330761931f438ea011bda57bb64a), uint256(0x1fb2e06e9339f2f17845c8cb7a6a79f10166226eecbcae6efe2b416141da5379));
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
