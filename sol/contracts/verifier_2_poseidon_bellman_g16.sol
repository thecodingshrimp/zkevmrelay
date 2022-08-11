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
        vk.alpha = Pairing.G1Point(uint256(0x096f6c9ed37ee44dcce08bd5e67e03b61780e5ae6655a5f225de5ceb8fd52e11), uint256(0x09723ceb7665392035377ac31068b1d33787328fa2287bf850942e4ed06d4a66));
        vk.beta = Pairing.G2Point([uint256(0x0e653f210f1645f32456b584009b7254e539069e3f68cb21a1433b0463c083dc), uint256(0x2d0d843b5fe0a65490936f683a739b6f3c11108ad99acc18d20802797c7d89fb)], [uint256(0x221aee4642c4734db30e81b76bf96351f68773a6a95a55e7d64bd03775018dcd), uint256(0x156e6cea9d514e534481d14df2b1a68bfc9021793d8abcc481379c285c9cdb8b)]);
        vk.gamma = Pairing.G2Point([uint256(0x05c91c137939c960d7ecc6274d926149b20c84c165c537f15eef24a4fd4aa1e7), uint256(0x1a7ff53c1cdc5b28d2ab5459d1f6eb4940ed4e7990f9343f2d4063fd0be34f81)], [uint256(0x17bb7970c89e8b50d23a24a75c38968238556b114024a39002275eaa33ec14d3), uint256(0x01deede1d20cef13c4fc92ac0d48188c51bdcfba7e3a227f4a9eed18c6c26241)]);
        vk.delta = Pairing.G2Point([uint256(0x144fb5da82054eff55bea0cb6b9179db49ba81d56394d8273ad4520342458568), uint256(0x2c5adf2010e1def684eaa23726ef46c52257a3c58977c9bc8bc7d2f883d656b4)], [uint256(0x0d33f6779690457027afae3554bdd5ffb028db2c13df57877b84442af079904d), uint256(0x088d6d51cd077c16f38374a8575fb7d74e26e4228f9ca5d91a64a146e51cffee)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x131d6c8d2f720e0e2f507c4e62553f5dab2251781fb469abff5639bbcc1e3a3b), uint256(0x2949201e2e6b59a8b527d1b723a196c2e668fc97a9f46c682eef9151f8d2b318));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x10c116328f24cee4878a280da062e6d88e3680d5567eba3b3207dc0f4b9a4d28), uint256(0x140b24105249791720ef834096498282d511e28c88ecebf87cfe5dd2cd638a9f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2117239505829c431d6098b90c02dea6452af9f4a33264f4355bdcb84b9adef5), uint256(0x178d42f66c6dc16697383bb40686b14171dae3ade7b5fa6dc470ef419727cc49));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1ab711db99d20e69e8369b52ff60b9dfede90e8b811089a5432474a2ab5cdf50), uint256(0x07592492510f9003075cc053dcd47c41ce35e291ada8e126e009bd3a7ab56ca6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x21c24f6268167953cd5c8056309824aafc25f6d420684c0eab4b8e86de2029f0), uint256(0x22f37189ce1e6e1c56fc376d05ef2689a1ed23ca5baabc6c7f5607099a4d8cb7));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x02210f77a0215a3f9773fa191c919c7dcd982ad947ec97c52f7c1e36605f2de6), uint256(0x299e28a71d18a39ee73574be0f6a0ce4a77b5a3771082ace3c9b0f2aae92f91d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1f8d009fdf3c5eef4cb5a4b1d4bcbd39f691320f6c5d2cf7371bcf39dddff492), uint256(0x0fca5d50a0ec304d9295bdb6d0a4db2c404abb2fcc1b111011ced6ee44ffbebd));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x02fcf9773433e61760eeb1c5ad7d3808a6325e9cff307c795fb1c2bd02f1da86), uint256(0x03d4dd5511159bc5ccd182f2a36724459505805c1c4fb4b87f7fa6d215632ff2));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x26b92a2e09966a414ebdb659871627c21102e677b9040a0d419b0573fcd4b5fb), uint256(0x15f115ca6e3336ee5ef9c2dcaff14f000bab7625cd8673dd7ad00e1747459e6c));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x042efc10dbf6175085b32d42274c86a0f98de28560830f23fcb0a5559a4f471a), uint256(0x0adbb373346333416e303d57297cf69a4869ed6befbe26d95f95391d2bde553a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1302fc0099c3739a5ab34f6ae5442f3321f3baf98878de187d87179217a14989), uint256(0x18b0113588a81e5eb682b0878aec25a1f46723bcb05e2f2f4d0b0945cb84e5ef));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x24ae098b87fef99365ece19aed61e18fd9d6309b13ed4bc21af97ffece2bda7f), uint256(0x200f54be36ce901651e1b7bf5bd283109da4169b8454b1c8c0ec57297057baf6));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2cf6f28fec7115526e21f4579ab651ed2091416acad1412b689c26f4f0c2d3c0), uint256(0x22cd88618c2c92837a03840669d0788ae31bafca6b2a47ed3d9c36a4fab3172d));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1dc77be13ffd2354cef20204712eb1c5b4d73803dace3c578b687293bc5694b1), uint256(0x05a3355ac0d0c478bdd57b91b904a01f31eb097497f63a7432d22aa356b952f1));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1649e89b30e7dcdf04e2b961a217713d6ee2f01879427758ce0e0cdf1980ab6e), uint256(0x299b75abdbb8c6ec15b27bbb4c25a8330dfcba90fd8006396154f45f23c09784));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x11256a8a6238805ee4638655dd369b56c8741cdc537d3162e360e28b6329c111), uint256(0x226eb6e175551625a1214415fac69906f95f97478bcbaeddb09cc4228f448628));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x12328c4c04e2f2e96358f9ea320750c67fe7b12598ba11090bf9e2713d0cb8de), uint256(0x189fdfce9330bca0c061992803c61037d42299108bc9df76aa0599fbc6ad0819));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2751c34705826727d5810d405732dfa7bb17216bb2f8d0e32a415219b16f0b07), uint256(0x08ba5b44aa2c3b2514d8817a81ffa9083174cb0533b4ee36ef4b765920391cee));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x21e12d44153bba8de3562a566ea88399116c8c84d4bf63c4dbac1daec7b430eb), uint256(0x07de8be73cc743c8b58e70e6b4dbb8876e9db9d7375e3357bdab679ca8f0e7ef));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2d5d04c759f6eb67edaaf44a0d3cb7346b3c689a1635bc291a70a782194455e7), uint256(0x10ea2127458dd63cecf30e1cd225488e4bb471a8bc6c856a12a99be2deec6817));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x07d4cf11ff8cb61f14961c0ce8ffce9a26fd05cfe0edf6ab761f3f9da69fa4f4), uint256(0x11566c0617662cccfcfbd78bb61c82fdcd327c1687cfd609b7b8440aa57ae299));
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
