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
    struct KZGVerifierKey {
        Pairing.G1Point g;
        Pairing.G1Point gamma_g;
        Pairing.G2Point h;
        Pairing.G2Point beta_h;
    }
    struct VerifierKey {
        // index commitments
        Pairing.G1Point[] index_comms;
        // verifier key
        KZGVerifierKey vk;
        Pairing.G1Point g1_shift;
        Pairing.G1Point g2_shift;
    }
    struct Proof {
        Pairing.G1Point[] comms_1;
        Pairing.G1Point[] comms_2;
        Pairing.G1Point degree_bound_comms_2_g1;
        Pairing.G1Point[] comms_3;
        Pairing.G1Point degree_bound_comms_3_g2;
        uint256[] evals;
        Pairing.G1Point batch_lc_proof_1;
        uint256 batch_lc_proof_1_r;
        Pairing.G1Point batch_lc_proof_2;
    }
    function verifierKey() internal pure returns (VerifierKey memory vk) {
        vk.index_comms = new Pairing.G1Point[](6);
        vk.index_comms[0] = Pairing.G1Point(0x192879fa5ab41e0ea04ed3b6779e161ccbd0d5afe072b9b9c2a593a57eb23e30, 0x2d097756eaca79314ecd8882cf7373609d988892c73784298d2194175922d55c);
        vk.index_comms[1] = Pairing.G1Point(0x2983df1fab0e674fb0e9e472b2a6d6a9f97250e069e1f061570dbab646e5af0c, 0x214ac7bca10e9bde366e4efe9948de737a13d517c5aa5307a4a7104859c72a91);
        vk.index_comms[2] = Pairing.G1Point(0x28f0d3723771b183f73af4463dc89d72194e79c6cb909e216fc2ca5bb34b01e7, 0x27e09ac579fe147a5c373b0afc2adf39b9b382010915a2eea1e3ae50b0bfe5b3);
        vk.index_comms[3] = Pairing.G1Point(0x259c2d75b351ab6c953114f03042b9c589034ab5ff4acccb8f1d071388102fa9, 0x15e34e9f5a1991f9c9319d2044edb1fb9445dc7b4b7f1c80160a90c4489b1259);
        vk.index_comms[4] = Pairing.G1Point(0x2f8ace906477fbf55cd2bc993fd1337e006adb535f23abd1a1a10e5858bbf99a, 0x2c25386ce56c22312cabd2a1e77b86353edc6795890ad3919f05848234fc6651);
        vk.index_comms[5] = Pairing.G1Point(0x0eefda6accb3acc67018cf10a9d3b2fec17bf6f107135beb970a6149408831a5, 0x194f63c6f90529399db22d735a557c16153c0c7cb0353f42ebac8f596cd9f15f);
        vk.vk.g = Pairing.G1Point(0x2b60061c59f8c9b8e48c84c9860f22ec231b5d4e8ddda1a40e00c5daced6f754, 0x2b1c19baaa018a333966195e4cea05eb491aee7fc6ad741cd5008cddc26bc4db);
        vk.vk.gamma_g = Pairing.G1Point(0x2a3e7076cc8e9f996dae3b4d18b99b2a3cbc9d5de1be22003372716e0e756545, 0x2f8fbb3e4edbfc084b458f79de72989688327ece9dd9eb5696012dc08c572cc8);
        vk.vk.h = Pairing.G2Point([0x2ba5600a00814513a5d3289b5a994eef2ddee3ccfce02804cb3d52f3bff1555c, 0x1354232f73b14eb8bc35516f8e3c41a84953dea5d2b2dd90c305c5015571cafe], [0x2858fad9dad3ea2d5c328d590a2a6f3c0a0e1b6fa3ca60739dbf7943e5e77dc6, 0x1194ebe95790ac5b7d62301dc67383f1655ac13a555f9ddcff3e8a00f2f1bc95]);
        vk.vk.beta_h = Pairing.G2Point([0x16814de85a4524051deaaba5a0f4edcf0ae6d623d32767e348eddf3b04dc1fc3, 0x1d5efc0ed98244c6a6c0c93cbd502b27c6486f6db984e8f46c7f4f76a8e491a1], [0x071387240c9d863de76128e745ab1fff1d64090f0dbaebe079d5e54cb5ed757f, 0x13d844efc9a112efb027a9cb11d3a31d3f603213373bbcd879c0b0c0bfd123ab]);
        vk.g1_shift = Pairing.G1Point(0x143b30eb5d797b11b39473cc81181322fab9a50cf7c1ab616fa2cdb71d8d58f2, 0x16a51662d2bddaecad3c24c155c041a0f768f444a7c2bb92a438421e9d355563);
        vk.g2_shift = Pairing.G1Point(0x0ad7ba3b44e760a8d10121c940cc5f715f21001ada54986adf9050f156aaa4ff, 0x1c6052f630d49e4f75842de20c7e8902515f5d2d73fe4e0888cc49d622e2422c);
    }

    function verifyTx(Proof memory proof, uint256[20] memory input) public view returns (bool) {

        uint256[31] memory input_padded;
        for (uint i = 0; i < input.length; i++) {
            input_padded[i] = input[i];
        }

        return verifyTxAux(input_padded, proof);
    }

    function verifyTxAux(uint256[31] memory input, Proof memory proof) internal view returns (bool) {
        VerifierKey memory vk = verifierKey();
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
        }
        bytes32 fs_seed;
        uint32 ctr;
        {
            bytes32[25] memory init_seed;
            init_seed[0] = 0x4d41524c494e2d323031398bc26200000000008bc26200000000007687470200;
            init_seed[1] = 0x000000303eb27ea593a5c2b9b972e0afd5d0cb1c169e77b6d34ea00e1eb45afa;
            init_seed[2] = 0x7928195cd522591794218d298437c79288989d607373cf8288cd4e3179caea56;
            init_seed[3] = 0x77092d0000000000000000000000000000000000000000000000000000000000;
            init_seed[4] = 0x0000000000010000000000000000000000000000000000000000000000000000;
            init_seed[5] = 0x0000000000010cafe546b6ba0d5761f0e169e05072f9a9d6a6b272e4e9b04f67;
            init_seed[6] = 0x0eab1fdf8329912ac7594810a7a40753aac517d5137a73de4899fe4e6e36de9b;
            init_seed[7] = 0x0ea1bcc74a210000000000000000000000000000000000000000000000000000;
            init_seed[8] = 0x0000000000000000010000000000000000000000000000000000000000000000;
            init_seed[9] = 0x000000000000000001e7014bb35bcac26f219e90cbc6794e19729dc83d46f43a;
            init_seed[10] = 0xf783b1713772d3f028b3e5bfb050aee3a1eea215090182b3b939df2afc0a3b37;
            init_seed[11] = 0x5c7a14fe79c59ae0270000000000000000000000000000000000000000000000;
            init_seed[12] = 0x0000000000000000000000010000000000000000000000000000000000000000;
            init_seed[13] = 0x000000000000000000000001a92f108813071d8fcbcc4affb54a0389c5b94230;
            init_seed[14] = 0xf01431956cab51b3752d9c2559129b48c4900a16801c7f4b7bdc4594fbb1ed44;
            init_seed[15] = 0x209d31c9f991195a9f4ee3150000000000000000000000000000000000000000;
            init_seed[16] = 0x0000000000000000000000000000010000000000000000000000000000000000;
            init_seed[17] = 0x0000000000000000000000000000019af9bb58580ea1a1d1ab235f53db6a007e;
            init_seed[18] = 0x33d13f99bcd25cf5fb776490ce8a2f5166fc348284059f91d30a899567dc3e35;
            init_seed[19] = 0x867be7a1d2ab2c31226ce56c38252c0000000000000000000000000000000000;
            init_seed[20] = 0x0000000000000000000000000000000000010000000000000000000000000000;
            init_seed[21] = 0x000000000000000000000000000000000001a531884049610a97eb5b1307f1f6;
            init_seed[22] = 0x7bc1feb2d3a910cf1870c6acb3cc6adaef0e5ff1d96c598faceb423f35b07c0c;
            init_seed[23] = 0x3c15167c555a732db29d392905f9c6634f190000000000000000000000000000;
            init_seed[24] = 0x0000000000000000000000000000000000000000010000000000000000000000;
            bytes21 init_seed_overflow = 0x000000000000000000000000000000000000000001;
            uint256[31] memory input_reverse;
            for (uint i = 0; i < input.length; i++) {
                input_reverse[i] = be_to_le(input[i]);
            }
            fs_seed = keccak256(abi.encodePacked(init_seed, init_seed_overflow, input_reverse));
        }
        {
            ctr = 0;
            uint8 one = 1;
            uint8 zero = 0;
            uint256[2] memory empty = [0, be_to_le(1)];
            fs_seed = keccak256(abi.encodePacked(
                    abi.encodePacked(
                        be_to_le(proof.comms_1[0].X), be_to_le(proof.comms_1[0].Y), zero,
                        zero,
                        empty, one
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_1[1].X), be_to_le(proof.comms_1[1].Y), zero,
                        zero,
                        empty, one
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_1[2].X), be_to_le(proof.comms_1[2].Y), zero,
                        zero,
                        empty, one
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_1[3].X), be_to_le(proof.comms_1[3].Y), zero,
                        zero,
                        empty, one
                    ),
                    fs_seed
            ));
        }
        uint256[7] memory challenges;
        {
            uint256 f;
            (f, ctr) = sample_field(fs_seed, ctr);
            while (eval_vanishing_poly(f, 8388608) == 0) {
                (f, ctr) = sample_field(fs_seed, ctr);
            }
            challenges[0] = montgomery_reduction(f);
            (f, ctr) = sample_field(fs_seed, ctr);
            challenges[1] = montgomery_reduction(f);
            (f, ctr) = sample_field(fs_seed, ctr);
            challenges[2] = montgomery_reduction(f);
            (f, ctr) = sample_field(fs_seed, ctr);
            challenges[3] = montgomery_reduction(f);
        }
        {
            ctr = 0;
            uint8 one = 1;
            uint8 zero = 0;
            uint256[2] memory empty = [0, be_to_le(1)];
            fs_seed = keccak256(abi.encodePacked(
                    abi.encodePacked(
                        be_to_le(proof.comms_2[0].X), be_to_le(proof.comms_2[0].Y), zero,
                        zero,
                        empty, one
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_2[1].X), be_to_le(proof.comms_2[1].Y), zero,
                        one,
                        be_to_le(proof.degree_bound_comms_2_g1.X), be_to_le(proof.degree_bound_comms_2_g1.Y), zero
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_2[2].X), be_to_le(proof.comms_2[2].Y), zero,
                        zero,
                        empty, one
                    ),
                    fs_seed
            ));
        }
        {
            uint256 f;
            (f, ctr) = sample_field(fs_seed, ctr);
            while (eval_vanishing_poly(f, 8388608) == 0) {
                (f, ctr) = sample_field(fs_seed, ctr);
            }
            challenges[4] = montgomery_reduction(f);
        }
        {
            ctr = 0;
            uint8 one = 1;
            uint8 zero = 0;
            uint256[2] memory empty = [0, be_to_le(1)];
            fs_seed = keccak256(abi.encodePacked(
                    abi.encodePacked(
                        be_to_le(proof.comms_3[0].X), be_to_le(proof.comms_3[0].Y), zero,
                        one,
                        be_to_le(proof.degree_bound_comms_3_g2.X), be_to_le(proof.degree_bound_comms_3_g2.Y), zero
                    ),
                    abi.encodePacked(
                        be_to_le(proof.comms_3[1].X), be_to_le(proof.comms_3[1].Y), zero,
                        zero,
                        empty, one
                    ),
                    fs_seed
            ));
        }
        {
            uint256 f;
            (f, ctr) = sample_field(fs_seed, ctr);
            challenges[5] = montgomery_reduction(f);
        }
        {
            ctr = 0;
            uint256[] memory evals_reverse = new uint256[](proof.evals.length);
            for (uint i = 0; i < proof.evals.length; i++) {
                evals_reverse[i] = be_to_le(proof.evals[i]);
            }
            fs_seed = keccak256(abi.encodePacked(evals_reverse, fs_seed));
        }
        {
            uint256 f;
            (f, ctr) = sample_field_128(fs_seed, ctr);
            challenges[6] = f;
        }
        Pairing.G1Point[2] memory combined_comm;
        uint256[2] memory combined_eval;
        {
            uint256[6] memory intermediate_evals;

            intermediate_evals[0] = eval_unnormalized_bivariate_lagrange_poly(
                    challenges[0],
                    challenges[4],
                    8388608
            );
            intermediate_evals[1] = eval_vanishing_poly(challenges[0], 8388608);
            intermediate_evals[2] = eval_vanishing_poly(challenges[4], 8388608);
            intermediate_evals[3] = eval_vanishing_poly(challenges[4], 32);

            {
                uint256[32] memory lagrange_coeffs = eval_all_lagrange_coeffs_x_domain(challenges[4]);
                intermediate_evals[4] = lagrange_coeffs[0];
                for (uint i = 1; i < lagrange_coeffs.length; i++) {
                    intermediate_evals[4] = addmod(intermediate_evals[4], mulmod(lagrange_coeffs[i], input[i-1], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                }
            }
            intermediate_evals[5] = eval_vanishing_poly(challenges[5], 67108864);

            {
                // beta commitments: g_1, outer_sc, t, z_b
                uint256[4] memory beta_evals;
                Pairing.G1Point[4] memory beta_commitments;
                beta_evals[0] = proof.evals[0];
                beta_evals[2] = proof.evals[2];
                beta_evals[3] = proof.evals[3];
                beta_commitments[0] = proof.comms_2[1];
                beta_commitments[2] = proof.comms_2[0];
                beta_commitments[3] = proof.comms_1[2];
                {
                    // outer sum check: mask_poly, z_a, 1, w, 1, h_1, 1
                    uint256[7] memory outer_sc_coeffs;
                    outer_sc_coeffs[0] = 1;
                    outer_sc_coeffs[1] = mulmod(intermediate_evals[0], addmod(challenges[1], mulmod(challenges[3], proof.evals[3], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    outer_sc_coeffs[2] = mulmod(intermediate_evals[0], mulmod(challenges[2], proof.evals[3], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    outer_sc_coeffs[3] = mulmod(intermediate_evals[3], submod(0, proof.evals[2], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    outer_sc_coeffs[4] = mulmod(intermediate_evals[4], submod(0, proof.evals[2], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    outer_sc_coeffs[5] = submod(0, intermediate_evals[2], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    outer_sc_coeffs[6] = mulmod(proof.evals[0], submod(0, challenges[4], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);

                    beta_commitments[1] = proof.comms_1[3];
                    beta_commitments[1] = beta_commitments[1].addition(proof.comms_1[1].scalar_mul(outer_sc_coeffs[1]));
                    beta_commitments[1] = beta_commitments[1].addition(proof.comms_1[0].scalar_mul(outer_sc_coeffs[3]));
                    beta_commitments[1] = beta_commitments[1].addition(proof.comms_2[2].scalar_mul(outer_sc_coeffs[5]));
                    beta_evals[1] = submod(beta_evals[1], outer_sc_coeffs[2], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    beta_evals[1] = submod(beta_evals[1], outer_sc_coeffs[4], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    beta_evals[1] = submod(beta_evals[1], outer_sc_coeffs[6], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                }
                {
                    combined_comm[0] = beta_commitments[0];
                    combined_eval[0] = beta_evals[0];
                    uint256 beta_opening_challenge = challenges[6];
                    {
                        Pairing.G1Point memory tmp = proof.degree_bound_comms_2_g1.addition(vk.g1_shift.scalar_mul(beta_evals[0]).negate());
                        tmp = tmp.scalar_mul(beta_opening_challenge);
                        combined_comm[0] = combined_comm[0].addition(tmp);
                    }
                    beta_opening_challenge = mulmod(beta_opening_challenge, challenges[6], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    combined_comm[0] = combined_comm[0].addition(beta_commitments[1].scalar_mul(beta_opening_challenge));
                    combined_eval[0] = addmod(combined_eval[0], mulmod(beta_evals[1], beta_opening_challenge, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    beta_opening_challenge = mulmod(beta_opening_challenge, challenges[6], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    combined_comm[0] = combined_comm[0].addition(beta_commitments[2].scalar_mul(beta_opening_challenge));
                    combined_eval[0] = addmod(combined_eval[0], mulmod(beta_evals[2], beta_opening_challenge, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    beta_opening_challenge = mulmod(beta_opening_challenge, challenges[6], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    combined_comm[0] = combined_comm[0].addition(beta_commitments[3].scalar_mul(beta_opening_challenge));
                    combined_eval[0] = addmod(combined_eval[0], mulmod(beta_evals[3], beta_opening_challenge, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                }
            }
            {
                // gamma commitments: g_2, inner_sc
                uint256[2] memory gamma_evals;
                Pairing.G1Point[2] memory gamma_commitments;
                gamma_evals[0] = proof.evals[1];
                gamma_commitments[0] = proof.comms_3[0];
                {
                    // inner sum check: a_val, b_val, c_val, 1, row, col, row_col, h_2
                    uint256[8] memory inner_sc_coeffs;
                    {
                        uint256 a_poly_coeff = mulmod(intermediate_evals[1], intermediate_evals[2], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[0] = mulmod(challenges[1], a_poly_coeff, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[1] = mulmod(challenges[2], a_poly_coeff, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[2] = mulmod(challenges[3], a_poly_coeff, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    }
                    {
                        uint256 b_poly_coeff = mulmod(challenges[5], proof.evals[1], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        b_poly_coeff = addmod(b_poly_coeff, mulmod(proof.evals[2], inverse(67108864), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[3] = mulmod(b_poly_coeff, submod(0, mulmod(challenges[4], challenges[0], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[4] = mulmod(b_poly_coeff, challenges[0], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[5] = mulmod(b_poly_coeff, challenges[4], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                        inner_sc_coeffs[6] = submod(0, b_poly_coeff, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    }
                    inner_sc_coeffs[7] = submod(0, intermediate_evals[5], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);

                    gamma_commitments[1] = vk.index_comms[2].scalar_mul(inner_sc_coeffs[0]);
                    gamma_commitments[1] = gamma_commitments[1].addition(vk.index_comms[3].scalar_mul(inner_sc_coeffs[1]));
                    gamma_commitments[1] = gamma_commitments[1].addition(vk.index_comms[4].scalar_mul(inner_sc_coeffs[2]));
                    gamma_commitments[1] = gamma_commitments[1].addition(vk.index_comms[0].scalar_mul(inner_sc_coeffs[4]));
                    gamma_commitments[1] = gamma_commitments[1].addition(vk.index_comms[1].scalar_mul(inner_sc_coeffs[5]));
                    gamma_commitments[1] = gamma_commitments[1].addition(vk.index_comms[5].scalar_mul(inner_sc_coeffs[6]));
                    gamma_commitments[1] = gamma_commitments[1].addition(proof.comms_3[1].scalar_mul(inner_sc_coeffs[7]));
                    gamma_evals[1] = submod(0, inner_sc_coeffs[3], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                }
                {
                    combined_comm[1] = gamma_commitments[0];
                    combined_eval[1] = gamma_evals[0];
                    uint256 gamma_opening_challenge = challenges[6];
                    {
                        Pairing.G1Point memory tmp = proof.degree_bound_comms_3_g2.addition(vk.g2_shift.scalar_mul(gamma_evals[0]).negate());
                        tmp = tmp.scalar_mul(gamma_opening_challenge);
                        combined_comm[1] = combined_comm[1].addition(tmp);
                    }
                    gamma_opening_challenge = mulmod(gamma_opening_challenge, challenges[6], 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                    combined_comm[1] = combined_comm[1].addition(gamma_commitments[1].scalar_mul(gamma_opening_challenge));
                    combined_eval[1] = addmod(combined_eval[1], mulmod(gamma_evals[1], gamma_opening_challenge, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                }
            }
        }
        // Final pairing check
        uint256 r = uint256(keccak256(abi.encodePacked(combined_comm[0].X, combined_comm[0].Y, combined_comm[1].X, combined_comm[1].Y, fs_seed)));

        Pairing.G1Point memory c_final;
        {
            Pairing.G1Point[2] memory c;
            c[0] = combined_comm[0].addition(proof.batch_lc_proof_1.scalar_mul(challenges[4]));
            c[1] = combined_comm[1].addition(proof.batch_lc_proof_2.scalar_mul(challenges[5]));
            c_final = c[0].addition(c[1].scalar_mul(r));
        }
        Pairing.G1Point memory w_final = proof.batch_lc_proof_1.addition(proof.batch_lc_proof_2.scalar_mul(r));
        uint256 g_mul_final = addmod(combined_eval[0], mulmod(combined_eval[1], r, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);

        c_final = c_final.addition(vk.vk.g.scalar_mul(g_mul_final).negate());
        c_final = c_final.addition(vk.vk.gamma_g.scalar_mul(proof.batch_lc_proof_1_r).negate());
        bool valid = Pairing.pairingProd2(w_final.negate(), vk.vk.beta_h, c_final, vk.vk.h);
        return valid;
    }
    function be_to_le(uint256 input) internal pure returns (uint256 v) {
        v = input;
        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }
    function sample_field(bytes32 fs_seed, uint32 ctr) internal pure returns (uint256, uint32) {
        // https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/models/fp/mod.rs#L561
        while (true) {
            uint256 v;
            for (uint i = 0; i < 4; i++) {
                v |= (uint256(keccak256(abi.encodePacked(fs_seed, ctr))) & uint256(0xFFFFFFFFFFFFFFFF)) << ((3-i) * 64);
                ctr += 1;
            }
            v = be_to_le(v);
            v &= (1 << 254) - 1;
            if (v < 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001) {
                return (v, ctr);
            }
        }
    }
    function sample_field_128(bytes32 fs_seed, uint32 ctr) internal pure returns (uint256, uint32) {
        // https://github.com/arkworks-rs/algebra/blob/master/ff/src/fields/models/fp/mod.rs#L561
        uint256 v;
        for (uint i = 0; i < 2; i++) {
            v |= (uint256(keccak256(abi.encodePacked(fs_seed, ctr))) & uint256(0xFFFFFFFFFFFFFFFF)) << ((3-i) * 64);
            ctr += 1;
        }
        v = be_to_le(v);
        return (v, ctr);
    }
    function montgomery_reduction(uint256 r) internal pure returns (uint256 v) {
        uint256[4] memory limbs;
        uint256[4] memory mod_limbs;
        for (uint i = 0; i < 4; i++) {
            limbs[i] = (r >> (i * 64)) & uint256(0xFFFFFFFFFFFFFFFF);
            mod_limbs[i] = (0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 >> (i * 64)) & uint256(0xFFFFFFFFFFFFFFFF);
        }
        // Montgomery Reduction
        for (uint i = 0; i < 4; i++) {
            uint256 k = mulmod(limbs[i], 0xc2e1f593efffffff, 1 << 64);
            uint256 carry = 0;
            carry = (limbs[i] + (k * mod_limbs[0]) + carry) >> 64;

            for (uint j = 0; j < 4; j++) {
                uint256 tmp = limbs[(i + j) % 4] + (k * mod_limbs[j]) + carry;
                limbs[(i + j) % 4] = tmp & uint256(0xFFFFFFFFFFFFFFFF);
                carry = tmp >> 64;
            }
            limbs[i % 4] = carry;
        }
        for (uint i = 0; i < 4; i++) {
            v |= (limbs[i] & uint256(0xFFFFFFFFFFFFFFFF)) << (i * 64);
        }
    }
    function submod(uint256 a, uint256 b, uint256 n) internal pure returns (uint256) {
        return addmod(a, n - b, n);
    }
    function expmod(uint256 _base, uint256 _exponent, uint256 _modulus) internal view returns (uint256 retval){
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
        // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return output[0];
    }
    function inverse(uint256 a) internal view returns (uint256){
        return expmod(a, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 - 2, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
    }
    function eval_vanishing_poly(uint256 x, uint256 domain_size) internal view returns (uint256){
        return submod(expmod(x, domain_size, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), 1, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
    }
    function eval_unnormalized_bivariate_lagrange_poly(uint256 x, uint256 y, uint256 domain_size) internal view returns (uint256){
        require(x != y);
        uint256 tmp = submod(eval_vanishing_poly(x, domain_size), eval_vanishing_poly(y, domain_size), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
        return mulmod(tmp, inverse(submod(x, y, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001)), 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
    }
    function eval_all_lagrange_coeffs_x_domain(uint256 x) internal view returns (uint256[32] memory){
        uint256[32] memory coeffs;
        uint256 domain_size = 32;
        uint256 root = 0x09c532c6306b93d29678200d47c0b2a99c18d51b838eeb1d3eed4c533bb512d0;
        uint256 v_at_x = eval_vanishing_poly(x, domain_size);
        uint256 root_inv = inverse(root);
        if (v_at_x == 0) {
            uint256 omega_i = 1;
            for (uint i = 0; i < domain_size; i++) {
                if (omega_i == x) {
                    coeffs[i] = 1;
                    return coeffs;
                }
                omega_i = mulmod(omega_i, root, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
            }
        } else {
            uint256 l_i = mulmod(inverse(v_at_x), domain_size, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
            uint256 neg_elem = 1;
            for (uint i = 0; i < domain_size; i++) {
                coeffs[i] = mulmod(submod(x, neg_elem, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001), l_i, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                coeffs[i] = inverse(coeffs[i]);
                l_i = mulmod(l_i, root_inv, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
                neg_elem = mulmod(neg_elem, root, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001);
            }
            return coeffs;
        }
    }
}
