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
        vk.alpha = Pairing.G1Point(uint256(0x051a58f4c42fe663af3f2d8e8a68ac058ad17f6975377a520c55d7deaa5a32d1), uint256(0x149e778b18a1390c11deeb6dba725276d3747486fbf788ffb806f0b2b8f75a35));
        vk.beta = Pairing.G2Point([uint256(0x07a9f2475499f1bc354cd7f090e0fa1e0dfb8fe75f7c07fd444e298bcc2e5459), uint256(0x2eeeadc8e33d6a98986eb677ef815a17d2cb5bce7443a92a9f9154d250bf9ed3)], [uint256(0x02024e776695019db91de0a65ad0e319962f7b1faecee8819d04872c2caa2a4c), uint256(0x24a027212a657f3d37fde79c0eb9c94edc76e47ac9d88c4484f1ba474883babe)]);
        vk.gamma = Pairing.G2Point([uint256(0x1665aca7cc493d898902c9845417962c28210c1ffa1cd3a21e1f2d6b37338385), uint256(0x2e3ab0493c779651ae00153be24c2eb10cb08c945c9ad2a5a2e91216425b2f8b)], [uint256(0x15a7b3b91d7ce61f7c0789cb331f5892496537b451ded18197a972fb1a855dd6), uint256(0x180194af99861a764804559fa779825fa59da4e3ef1a9cc5843a3e771b34407a)]);
        vk.delta = Pairing.G2Point([uint256(0x0468838d3b254ebf3122588cf1013641816ecb248624796bb36f1bdc2edae2f2), uint256(0x09841e5a00dfe49445a02d4494ad85a8f8acab17708f9c949d0b8b602207c450)], [uint256(0x29ecd48c8a6878e27b2802d028a90cf00abffe8f4eb12f16ac9f22e85eef639a), uint256(0x1bb9b557e62cbc90bb793dd431be6cb9f57c569e1dcffbe5d79f754e4ebf043b)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0496a93226523cb61872976dab5fe439b175142f541bcaead487a0161387d635), uint256(0x178feb802650edde577e263551f0a56fd71bd0bb78eec53975d6f2c320689a62));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x30565c194764146d5c360e2077fd30a10db0ca5108a462db0286b44da78a7390), uint256(0x0293153947ccd49d4f5eb950cb0a986a36141878b87a01c886067d89e87dcc7b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2bf582fe2a036f38762bd79c2d7719c0476921c25727169a2d0279eb11db7988), uint256(0x149cf9602c1f05b9e0336ed0df54a6c13dfe6fa6e9d12d579dcc47c3fca815af));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x280c63a52594353f21183cf1afb8441503161e4dd2ee71be456366493bd0d8d4), uint256(0x2a0f8afe007104f195f3ca8cf95b88d72be52fcdaf76ac71b76e841b75fd62c1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1d4a44e5e77c659fd6f4e158195058df6374843ef3311f53824ec9a7ccddddf9), uint256(0x04df0ccbf329172416365464d9384dfe604693484bfbe1f3c6653d70684bc2f3));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x028a7f50335f149c4efd1b14bec689cc766441f9e790603d9d54cd5da9d0ab93), uint256(0x0073a4af6603ef33a224fdb87492ecc2a8d4c9a3d48aa52ffe2bd58c3df9957e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x29b9b1b33c8a7692259fca6006da5a069afcb3e0ec0066903aa60bab96cdb3c9), uint256(0x2b4922b99b162ebcb59454e7b2388454cc2ff952a24a5df0dc3cc54061adee06));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x04e5b6fe4f99a225b877599e884fc3180582621c1996e44c131bf864cf381c1a), uint256(0x1e7a156ea36edb4733efac147d4f239d9bf2b5bfc6012bc2e943faf70221cbd8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2723ab7edb5fb600df6451d1f94549ce5c48a91329b310a513c8fc49458e7a53), uint256(0x24e399951d57180df6a69b3ede3d79264027c26b44fecea91955f081125ce04b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x209a54db86026a4d5d30d70aba71db74eff032b88887d36e00835bbd917ec8ed), uint256(0x00a7025099136964a3cba4446c6069932cb3620a802f36296d8a7b49551eef28));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0145dd1919e7dab9605a270c15083c9d097dcb7ffe7260927de091c2b40694b2), uint256(0x2a7c47ec2e1229e58cfec6acc08f0b217b12a42e1b39c2e5cdbdf1a2bab5db2a));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2d0fdbe40c6fd902d5ed2d454c87f626f74fcc4b9077ca5d0a56d79ed2ea6297), uint256(0x2d93f589bb9061e8fbd743867828147af4e592b9d3e2297a696fd5f39581afbc));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x22bb418f7890012ad114cca316a52a140d83094b1d025e76de235f278d2ad762), uint256(0x1d1f51517372bcf5559df821244b3b8f486c94bd61f414793ae00d28c20313fe));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x16fc3f195dd8530f7eac63ea0b627347f0bee89873ab0630aa2a97138f2f5734), uint256(0x22aa0bd533f6dfaca721a24964644a9a667df8f7d77a19ee34db022710dd0bfd));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x00e9c5a61c7b527b4c55f0ea4516f3caf1106cd688294bdeceefa70364fb1419), uint256(0x078726a50266855e4ecb77ee9f90bd5f9a566882fe6ced57d21003cad4ebfbea));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1abf9dc83c0e344a1764d52b60c168d0bd9a43024ce7e1220e90f096a31f37a8), uint256(0x24c522a79d19d508562fbbfacc932c182f4edeecd12eb7baf751ff42c7429b28));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2d61560ed0001535be152b2ab3a270a510aa89b83a27a0150651f6c5c541ffb5), uint256(0x09fbd4854d6bdae1690cd64d83708cc0eadc4c9fe0135f772c0367a32058eac0));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x249fbe5790c1becc7d9abcb37b09ccb09250d059ec562ecfd0a1b111dc215613), uint256(0x1186eebba310b2439c6e4f1ba9cf2bb19bd7948947f696c6c21631929150fa33));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x111a50715bcbe17835f7e1df09dd37d161cc0666495f6960ca1186fd018ad6e6), uint256(0x03aad552a5fdfabc4e5e319c187fa77dd897143ae3d45e5e80589ef05b49dd38));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x26ef19626a5f7a124985e56b8cf9e10a05b6a69afc18d91e525174f8811ada4c), uint256(0x25783982852bd8f45c12e0b4002bea37c7021bc3e10dc6aebc8d485f859aba1f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2ac2d5437d3a68dc7bb4cdf391bf5d4e54cb8167879529e6184142f6602f6c14), uint256(0x0eaca9b19dea01daa12129ab331205c87e96882c8667349e0e602f26ef263a7e));
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
