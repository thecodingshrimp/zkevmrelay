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
        vk.alpha = Pairing.G1Point(uint256(0x050d25f5a8757417639abe08cd82934d7f4c3ba70124676c57c925ffdc125038), uint256(0x0e07b71d2b794a05f56df2ead33e315545d45817d6d698eb85ecfabd8f80a8c7));
        vk.beta = Pairing.G2Point([uint256(0x2eaafefc6f53ea48a78a351b5d83cf23ed390652574cb8dd10e9cfe9489e420d), uint256(0x17401b27c9d283649366ff809431fd8aefb78d4d9b0e9f64819d820c98d49fe6)], [uint256(0x0e7733a3bfc917fcd9a4850a4ae7c1dc9207129ee979f6cfd96fa9a9010fbb45), uint256(0x2b16a1c9f8de7bd4704ffe2be56348da023500559dcfc8635418444fcf740e08)]);
        vk.gamma = Pairing.G2Point([uint256(0x1b14aa421c5132e929d867af570f02bd6f5702ef26257e76360dae31224dda45), uint256(0x0ec3501ddf001b4eb51c23eaf5792963f149c8ead302ee60e73363cc4d2cae3e)], [uint256(0x1eb538937f961da20c513a5f535a1cc3d38ff061d15bc9882226a4e7b79c217a), uint256(0x118df14c7e8e4eba1c84ecc28a81517706a7f47201a369162b3d6031ff2158ee)]);
        vk.delta = Pairing.G2Point([uint256(0x00bcda77cac41469b55b80235568827ef9953b0651f605653bb928151062d428), uint256(0x2cd55a968472a827e93bb719c0a144ad7e0274df26ecb6718b966d19b4ff3870)], [uint256(0x0aed4775861aaae4e86264c6b67a98ef1b6d875bfebb8b244189b23f0665160d), uint256(0x1c7531847609e98a5f33d4a786d574373ffb3b852edff8f9f332d0205265b6a2)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2183d5fcb850408afca09c5d3815ac62c4b34069a3932c01174bf72604dafb4f), uint256(0x1a98f547c9250466eee0cbe28fd17f61592d2c5bcdee2b4fa252ea9eb7d7bca2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f23a339af4b85fdb81cbfa04df60d2a4ca5c7350ac7d05915b04535deab1654), uint256(0x2549f504fc2edf83b4d83b03f34b0423758c7d173d785bfded1c97d6705a9539));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x251c9f40e413a0fa4cd49f559ab2d2bbb7d1a53d01082d2f5505904aec8c15d5), uint256(0x2600d79097f8b4bf1ceffb82fa84ddc16170ede2144930fad23fbb8919b236f6));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x20098aa22757e6833b84b1e482f0b2b5b9cdacbd7b56f01c56fdfca4901066e3), uint256(0x091125bdf1fc30850ee986c6516b50fd5bbe7ec4b5dbacd9b88cfce7c7a5b669));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x252b609258b0e74de13ad78765a7c8f2975d058252d26398e2b9e27ee44a5db0), uint256(0x0b52ef28622cc67fe119451bb3eb61de136a82e51d3e4ef51af414c22569c9d9));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0cc9e3856d0119299346af9353c36cd4478a67b5252bbea1c80aa8cb71fe3a6b), uint256(0x08ff6bb92ccda965fedbe72d7e22894a0cbea9e5d7a8f4379c493ec1c86a998f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x15d621df27aae0ea6fae8e0c620c82f0581752a1a845e13946ccfcc241489cc9), uint256(0x24be4046408924033feb5ac0d27c27c4ed12df328e5d6f5b203eaae24c21ec50));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2159f9aa733ece4214fa7dac5a8d4ade9314862c7147bed59823da3b695acfa9), uint256(0x0409dc7cd9edf99c8cd8da4be48d727613d1050d614d9a95bc7a875f2a0272fa));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x00d65f02b7881180376452cb6e7c376fbebbb4c25569973f6f1509110dd0b0f6), uint256(0x21ad9cbb7096bf057900f14562b941f7a775f3edd63f95fcd27946ff0ae32648));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2ce86d5534bbcc800acc978d0b519f303d2893e7445026fee4627e1d31951e39), uint256(0x25353477279055049e6660c26350bdca6e59add16ff3417d967d1e1432c0fbbc));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x00c328e20d7f9793fe0ceafe7453a4a87fe0fb827ed6e4854f10a55733f9d61c), uint256(0x2c132fc4d604effc5e3c149050c443d86ce083fbce30396540ebbb5a604cc1f1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x051c0e2d3ba1d4603667226f24f9f1a1039eeb09abb9dfb6581e19fb12e936bc), uint256(0x1f6a20322c9ce5af1dd451945956a84125519f56e209f7084f05ca3d466e4e17));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0f732e508c6090ea69f7ab77d84cd649164dec1d42699aeec36cdb2d4ca0ba43), uint256(0x25d7709f79f9ac093107fbd055635b8f04ca02ebfeb2ad834be68e17cfbdb69a));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2b68482ce6f30ec68f8a16face8c1571e57647d6cec1d118fcf64e28a5e5627d), uint256(0x02b143d6489f69d576b0f77ea45b3acff885837f546269d73d0d9754bc891f89));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2766e1c52087411208a6a19a91506ff08b83094ccb99feea0d61d11398a8fc31), uint256(0x29dc0f0661bd490d4c3de9b2e261f7a6d7d6aaf2582d42e7dedc2a4b9487557b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x08c48cee479c472b407410e25ceb8b447ce53f4a7893a309be5c64128c03e13f), uint256(0x1caba7e681eb2590383e33378b02ed8a48775f607e8bcdfc090d5f0f09fd5ad1));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2921906ed572d501d9cf88706fb87db3c363da70937cffbeb98d5604b893aacb), uint256(0x26016dbeff508219dda2d163b1966f2b2fde3679c40e576924a499ce20990b21));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2bc76b2201ecef5258b920e84a248f827f8b9abc279c36365dbbf27edbe05cb5), uint256(0x23b519504bdb96b707a5b4b6edab417d7fdbc86dc23f43c4f6e3d1133337ce34));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x133c988c9335c42bee6efd94071df6ed758b0cdcb24abdde539eb64b682e1496), uint256(0x11c474d1e0d6c2698f45fdb9804ad6766a76b24b9f129021d633a2f504b60c9b));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x044ef71caf5ea01b920a113632dd10700c17172496d594bf1fc20e4a9be72e91), uint256(0x27cc021277ff3a98e364555ac03cd4f6a411b8eeff01d6ea7b0d342e88f9749a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x28b740078128fecc79b52aa7f6d9b7995f143e78fc1c751521a85638c00bbb94), uint256(0x1b4312d012ef9a55c921d380296c443913a46fb23fe3537736404963e14ea8da));
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
