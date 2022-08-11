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
        vk.alpha = Pairing.G1Point(uint256(0x0223c7bb14e9114794d04b4bc0b867ca8fca31f6c219800ac6353eb4fd4aaf38), uint256(0x0800281ad1eee7d0e46513d53c8d27ba068de25322766dff62d857f00dba29ec));
        vk.beta = Pairing.G2Point([uint256(0x01bfc756844ab411e38132498f2661c9c924d1250db259a1791034f9ed47a497), uint256(0x205242b3b9b9acca97cb5933404094f5faba447c22ae940c32ceb803dca06d36)], [uint256(0x18b2b997bfa07253a7d87a2dede30c514a951036d8356f4e80bb0bf04f278843), uint256(0x22619c5470faa4726fcc7e0f8b0b4dbb9edb3ada2294c4e66c063aa0ea58a693)]);
        vk.gamma = Pairing.G2Point([uint256(0x25eaa0061f41014bb5a56ad42e1020d1e14851a643741e5e73dd243f59980f01), uint256(0x0cabf411134ac7c8637d508071ca9fc6cb9ee38acf9ddadd54a6aef1a05c1446)], [uint256(0x229fd253bad430cba5fcd82992beaaf4ab8397edff663eae116a8d859b87ed27), uint256(0x0292ae1153b2386768e1b51dde12430a47014a55dcd0b6ae622c9a9a5751b633)]);
        vk.delta = Pairing.G2Point([uint256(0x0f2a3bd3fa1b19d7dce1f755ab20b9b74849be7dc7b9d209cf0cb89bea7b0265), uint256(0x2537d4ee5fd2bace7377ed5d5248a336817c2c6b08acf09b8fcf3ec109144823)], [uint256(0x104283d72fcc178ba0773bf3d9a85ef374b5aef70586bd73136bcb9f09cc2059), uint256(0x2c98f15547aae613d79b527ebf07a41da65e1308e1b71d521b7c87042f8b164c)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01d97135d2cc29cce288671adef12b33fc746809d58523e13ebf2fdfbea0f6c0), uint256(0x0ee2773e83a4720ca4f1aab91cba022fd1381a1cbe30d69852daffd2e38b1267));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x162ab04bfa1ef0580e7bd08dcfaeff36eaa7bfe4bb825569517156fc23ebce69), uint256(0x21c36fbbd1e4e378fc03f0bc1d7060211863d345a6129bcab4da1afa576c3cd7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x18fb30f38437f8ad46cb00ac208170d5c75d6d00bd7ff4383a1bbaceeaead694), uint256(0x029808e2aa1e675bc827ef6c0923b320af64d911d203695d0cefcc4f22fe6d92));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x01356d262437ca04087bbc2110e174f31a187537c707efc46453992f3f192022), uint256(0x1692fdd5881b53207b8b17cd7c7f38622967362748a8c9a7211ea245d1afb727));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2acb60e2e7570456516fbbd7d42dfe3934be877549deabcd656904501f2a23ce), uint256(0x0fc36c43f227b56753bedb8397fee6ffd119b82744148e48c0feb74c45754b6b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x18b77a0f9929a7d4d8525a223a90a59ae44b1c72e1460c44448b93c7647917ec), uint256(0x2510c06573988066c9c6b4e91910b1efd454907c0a06786b8a8935f86bc48046));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x294e6200038d23276a7078b26281570f7aacc15ad952f178878a7cc2f2d855ab), uint256(0x14113b85f44439cfe0244e3a4e7f854b29b63b289ada3b20297a310d8e7a801f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1f3789b8090b64f52755111b18979e9082a21dfb007dd7d0ef6ee0963e620d67), uint256(0x12ca976c29cd5e195ff1719594cd7742c8f306eabe3b687f66de2d8519b894be));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1ed6c7768668fba5d37d855a54905cb74b37d9e72ee25d2f8382e56284cae2e9), uint256(0x0b611a9087f072de66faa3b8b679918c28be519a8b73a1c992db5e7259dce7d8));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x109506868aeb1ec226be443d894a654c03be7ec284f86a5800db48f28fe27b91), uint256(0x1d0a2d7de524a4c1a3e44088240802c192e753ac84455e23b0e75eef112f429a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0df7cebed69699d83d05b9d61e5bfb87b60d049b90625d4fd85b51bc069d9145), uint256(0x1692553a7e932a564d892526eda16903dfcaa2ba05ac9df90b40e543b9b2c147));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2b14a012e5a97f78d48900a0136af77c70ded85bea9258f7ddd9911db007bdf1), uint256(0x29645cc033c8cf7ec6382749e236756b767a8a0ba6bf474c13b4f5a598e4ab32));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2f5fa6f91bbc4ff77a5f0555935b0ab965d3880f1824c75867abac47ba3b232a), uint256(0x0468eb30b7e31bf30cfa8e2aa680d7d192c5ef33f28c5ed939e1f6506bdbbeec));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2362b6d7243849e5994e3ca0ab7126add6afedde3dbc40b4108409beac9379fe), uint256(0x03a6f32705ddb9a563c2844f40042f3ac4782bd978f6a392d8f787aa87677e1f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x24494fcde410a98025e6a341ca5c4841f7ba753167f4c9108dbc497373143a5b), uint256(0x07e32bcdf2e9ea070e7d53b2e97355df70fa3d035eaac626ee71ad9bca988437));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0c2b708936574cf97e488f9dce282bc38bd827de48b03894155188d041a60e87), uint256(0x05ee3ef15d2670e7cfa8ec95fadf76c2d8e1f9c943ad7277de51c31b37a761e7));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11b0fd3379051eae57abcd3455fc5956a6079089b0a21ba2c17516505682a751), uint256(0x062c7eed1a3f321bbeea9a4ee500300212903b75ee54c4c2c42e1445d3e4a7a1));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1c2b1209da07ee3dc5edbf8c159763972b1ab2ff2f5608bc90f27c0fac30272c), uint256(0x0891a65f83529fcbc26b7b881c0850c95c163b29f9fd81afbfde88f2118774ef));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2e56081a77a8dde72f1b75673ffe0c9a992165dc53b170989b3711ac9b053c31), uint256(0x2482be668bfc3fe90f061b579b890fad15ed8c919c237bfa1c99c70f43dc7cf6));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x082035d463991fd2f37459fab6fd3f883730a01b2a511d472353502652b812bd), uint256(0x2b39e0201209f66aabe68c5d222023faaa5b059d03fc2cb2b1280fed95048ebb));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x17c6b568c61952183b5882dc8a0bf4186deb0066329764572a58dc4dc64930fb), uint256(0x13b985eaa78ce764024a3e7494ee4e91055785e829c9d8d751065e429035923d));
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
