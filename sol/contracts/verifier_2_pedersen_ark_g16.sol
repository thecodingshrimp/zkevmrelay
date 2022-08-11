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
        vk.alpha = Pairing.G1Point(uint256(0x0d6af1c4a95a9a5632c38dc14f9aa5100b7bf04ccb042b087b5c3373def7b563), uint256(0x060e3c5b39c4ce0cd06281adbab7364867969a17d4331586e3d7d07cd446b778));
        vk.beta = Pairing.G2Point([uint256(0x21d326bb503329af3e1ff60010a724e0f2e359b076b65bcc22a4bdc043a1d7f0), uint256(0x2fb6de9b6f32d26b20a4dd6ec6d804dc243c5ae5ec9ffd79e9d3e5078fe58a6d)], [uint256(0x1d92caa687878dceeedb19f00034af37c515695e734076fd8c1ed0a3766cdeb2), uint256(0x2f3556a025039a7a2009bd00938c35c1772f5068547aad677880edc1c510952e)]);
        vk.gamma = Pairing.G2Point([uint256(0x0cfab345f0be5b9e87669f2b5e06e10ad7439f2b1a05ff124c8c9d380fc57b7d), uint256(0x071e56d3d9e60255fed690990c066ad07f8938d36a5419273ade218d9ca13fc6)], [uint256(0x161f872b6a0f17fb0b914258951d6c5ebb346578731cacb105702b0feb44451a), uint256(0x1eddffab86266a8f9d0940e2dfc9c109ec36487c9ae638748bd8da30cb87b79a)]);
        vk.delta = Pairing.G2Point([uint256(0x21fc37d009f855def3ef24873f3517a2668f7b4c9e346ec690f34982f9020388), uint256(0x217d36adee633337af9c5483338e286dc84ab60732c3899fb5fef7ceb8107b05)], [uint256(0x12b888d2d0a77e4ddde43b986537800859b477aa289414226041035613af638d), uint256(0x10e67a191be39ee00f2b3f692d4c43878bdaa6e880705023f908552e4126a3cf)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x19ce18f4b1802786ea1f56df96b998889792c8763a520e945d7b2e3e495c5f9a), uint256(0x244436af2fc9c6cc3a28fd51249ca10a7deb78cfdca85861bfb92570a6bfd27b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x21ffa3151a705ed8c64b48bb653d3c2bc29cf36472577f82738a41c203f41c31), uint256(0x011e1cbe23be19dcd94f1c0988296b7af1f6db26c3b62dfac72db75dcbf9c403));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x04d1899aa88edcfaff876ce99f89445926ec6f4e3e0b90a0ac91ca88493de485), uint256(0x1323d43b9b7321c364ea5b538e6adee14d765e576fd281384fb22ea34704c110));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x29b8d4e062ce155b12563a817c050420df66b0b2046d5e0e0c26cfb4b270aac2), uint256(0x1325b4be74e2295663c36bbdbdebc2211f3417ee7070a84dd5e4a20a61fd858c));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1804282a1187f6f9d4eec41f1f9f6b814304c5ecc2ab03fe27372c0d084eb56a), uint256(0x246c59c33fc1f26d6da5628bc15b37d34c64a5e19557ea017223161803375840));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x291296e17e944ef8b8632d8e3ff9081a6a9fbe1a56c1a3caed78d7122257712e), uint256(0x148184c3af066e22a29f4affc54add9b88743587391454e4a083c47c9432452c));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x136b875d176bab90238103f2bc9608e07c5f6da4b2bbadf55eaae36066d6fe6b), uint256(0x08e855d9eef8a0458405f89ae203ab2ed4ca701d30c8d5bbd87e11490998cfb3));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0250882cba56374a11186c6b5f08b5b17a7539c4fede773134fca8f8531334b6), uint256(0x232c3a7bebd7d8a7538401451d18613cc05509efe01333d1ef59353d4ba4a086));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0f5696aad4fdef3eb8740fb2f09f9d1d77f55bd85a656f0a0c9c9af689d162bc), uint256(0x1a142857e67fad45efa37df0ca5c7a8cd30787780f30507fb414c87a2a25bb4f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x15a69771509b55a30da474dae03bd8c3a137f0a593ad1a71365d8a82bef5464f), uint256(0x013aa56b69acb3e9bdcd13ee4bdd3072cfcff80977a9588b91d6c88980d6ac26));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x03ffbbd166a29a1df8dbbc691d6c7027d40c76db2ad4ebf239b36d42cf006a47), uint256(0x1072eecdd4f5b86460221e11304ba3f993aec75cd24efc9c99ceb5cca2ce9251));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1f901445a53ac3fc24b4c66d1c7599a474e8d4f7b97a18fb4a646e6526a7202a), uint256(0x187f28bed76b034dd75fec4a4ad797834f2274a56e0cbbe7fa07d7a06c0a3055));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0119f43fd428936fffd6431341c847dffb10d3c01250de7007505007b65a7c98), uint256(0x23054bcd73f636979d802ab6f0387972c4aa7455ad1cf1811e8fa531d50265b2));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1d6b1fc8a73045ac69b26972abd4b1a584f150d900ad09e9659e2c9c8613a858), uint256(0x0e680a09cce52e3cfe281831c7290a080e70071654af57e06dcee9e14a4d206b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1b8af6941ae6c71253f60dad84c92a8f7166d004824f61a1ec3bc86f2641439b), uint256(0x261b82cec55d30792adeeaf8a3a66234f478ed9fb9109c1593a8aaa7bcda9643));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x15a049e9790eb34fe94efd031a7f588dd11cee753a496b1b0f7ffd48a081a3cc), uint256(0x0e15cdd725f5d147fff3d22a80195f9233d51fce91c76a8cd5ed84a4670506a3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x14528a195db475e225d6e45f9ba20577b16c9fd42164c57631bf89301be3286e), uint256(0x0c123eaba2b9a90953841faaecf864a71400b7649b8a665d4f4e33b5f4c83baf));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x206155c11450f673e4093cc2234c0824ac77085f54abacf15ffd9fb4df228b25), uint256(0x2d85c0488677a5e6f0f354438aa710947cece594edc21f6621e4c512df807e4d));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x00045461ca27526edd4c8e82851ddcc4517ad84977da4db687c589f506516007), uint256(0x185783e97bf89d120e64ca8d738149413de913a522c25bc8f08e7ddf000ec78c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1a4ef8e6996f56a12a0dfde73319ffdc9591f8a43d952e5123feb6975b6741ce), uint256(0x27ba64c8f6311ba6628bac705eeb786c7c4ac8c5342c3086e9db390bd065ebe6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x19a6465df3a69a1a312262bce5d8f8a22ee557d5c106be4de7885b7b08c2f6df), uint256(0x26e12ef73029ebaff78de146e80fefeea59b3e1aa0c5262eea38a0c664b8ee47));
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
