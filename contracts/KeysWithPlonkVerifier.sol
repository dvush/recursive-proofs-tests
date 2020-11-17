pragma solidity >=0.5.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./PlonkCore.sol";

// Hardcoded constants to avoid accessing store
contract KeysWithPlonkVerifier is VerifierWithDeserialize {

    uint256 constant VK_TREE_ROOT = 0x0040537a58863883e82f2b98e5e55b0074c2d9a7841cb60f86b69441df9b58b9;
    uint8 constant VK_MAX_INDEX = 0;

    function isBlockSizeSupportedInternal(uint32 _size) internal pure returns (bool) {
        if (_size == uint32(630)) { return true; }
        else { return false; }
    }

    function blockSizeToVkIndex(uint32 _chunks) internal pure returns (uint8) {
        if (_chunks == uint32(630)) { return 0; }
    }


    function getVkAggregated(uint32 _blocks) internal pure returns (VerificationKey memory vk) {
        if (_blocks == uint32(10)) { return getVkAggregated10(); }
        else if (_blocks == uint32(20)) { return getVkAggregated20(); }
    }


    function getVkAggregated10() internal pure returns(VerificationKey memory vk) {
        vk.domain_size = 16777216;
        vk.num_inputs = 1;
        vk.omega = PairingsBn254.new_fr(0x1951441010b2b95a6e47a6075066a50a036f5ba978c050f2821df86636c0facb);
        vk.gate_setup_commitments[0] = PairingsBn254.new_g1(
            0x2c6fb0fd7405044f5ae0acd13e0beec59f55db8718a6a5a37f21dd38cab5a169,
            0x2452bdd4b8abfcb618df76d097d6fb6f69dd0c6178e237ad4da92bf386162a94
        );
        vk.gate_setup_commitments[1] = PairingsBn254.new_g1(
            0x2932b281f8db24ee84f170bf4b309749931f128f0bed1d6baaaab38b04ed588c,
            0x20c4b70358f33c095cfa9886269340b139feca833ca4181b389e6e9a38306fb0
        );
        vk.gate_setup_commitments[2] = PairingsBn254.new_g1(
            0x293b159ae8d8e6b269f1a117b5946ea3d4030f58db08e5ce1591a216a625b8ec,
            0x222a805979ed94defa5f48cb9f0eeb55d55832120eabb31f87c7e2668d465f59
        );
        vk.gate_setup_commitments[3] = PairingsBn254.new_g1(
            0x1a14b8ba7febd9f5142d2041a706426693325039e6d4d17ca51eaba292806c1a,
            0x1e22671c61578b8d6eec3ff0ae43c3f7e7f3c0fbff7c2a4c11e769edbafcb38b
        );
        vk.gate_setup_commitments[4] = PairingsBn254.new_g1(
            0x1a6f7847f227789c4754e9479510976aa5e1342b7208773fd784beafcb6cb20b,
            0x2c370ddb50271677573cf932ee9eaed799295fb183f1846e83117f39db28f04d
        );
        vk.gate_setup_commitments[5] = PairingsBn254.new_g1(
            0x0e7ec141b347c8fa707e9f476f2bc927f0608b6965f4019965c19ab0207edc30,
            0x15795af02b2feda16baee986681f70520426af30f24a8eae3f9b5fa9451427d8
        );
        vk.gate_setup_commitments[6] = PairingsBn254.new_g1(
            0x07349f50fd3087c4bf86625fe76d2176c6e55c6c976ca8cc3d22b8ea472e9d28,
            0x2af5bc5a5c4411a277384835ed7db5e59fa920ddf0db8bc43a8ce5ca05c864c5
        );

        vk.gate_selector_commitments[0] = PairingsBn254.new_g1(
            0x134e83d86f0222093e05c39371b6fd1d9b7ffad02ec30e67d1c7815fa154d3af,
            0x11dffbf423562a2a65b95610339bae7dfa37d302a68232aef659411f1f82a54a
        );
        vk.gate_selector_commitments[1] = PairingsBn254.new_g1(
            0x1a76533af9b6199391dc8b03ce4d79718a4d91db3dbb97f40c9bc5e1f61015f3,
            0x1979af2a7794033786d1db7096444ceafe40b8aa8304735d43700abdcdbdf11d
        );

        vk.copy_permutation_commitments[0] = PairingsBn254.new_g1(
            0x02f6f51c35ebba8aad1fa6f24dbdb757c0e1c3415607483e0033a6fae70b0c3a,
            0x0ee7559170aa6db2a1ad0fa7c240fe04c7d135fb662cdf8baa4a1ae2b6b46e25
        );
        vk.copy_permutation_commitments[1] = PairingsBn254.new_g1(
            0x203d6b85c5380f179d1e58c5eee1443bdf6b03ffc32e8c14f7267eb3a1f76484,
            0x06d9aba1ef111ccd40ff26ea25ff800350ae6ed22b33f3bdd1e148ef09993e26
        );
        vk.copy_permutation_commitments[2] = PairingsBn254.new_g1(
            0x241337032b391d67a3012ab3ab41a2f867286bfcb7a1d32049338935f6e3da01,
            0x23c595a3b8675f0c571a05c936552ee4ffafc06fd5c43ed50eb160a90d444688
        );
        vk.copy_permutation_commitments[3] = PairingsBn254.new_g1(
            0x126e711caa0b7fd7f0e973cc8757b20ac47330e0376032b2ab213ec17c6a87f2,
            0x1b49e5f6a3c10d6b0061d1c13288f67db09e5f480ac246269d426fa7922c05d0
        );

        vk.copy_permutation_non_residues[0] = PairingsBn254.new_fr(
            0x0000000000000000000000000000000000000000000000000000000000000005
        );
        vk.copy_permutation_non_residues[1] = PairingsBn254.new_fr(
            0x0000000000000000000000000000000000000000000000000000000000000007
        );
        vk.copy_permutation_non_residues[2] = PairingsBn254.new_fr(
            0x000000000000000000000000000000000000000000000000000000000000000a
        );

        vk.g2_x = PairingsBn254.new_g2(
            [0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1,
             0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0],
            [0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4,
             0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55]
        );
    }
    
    function getVkAggregated20() internal pure returns(VerificationKey memory vk) {
        vk.domain_size = 33554432;
        vk.num_inputs = 1;
        vk.omega = PairingsBn254.new_fr(0x0d94d63997367c97a8ed16c17adaae39262b9af83acb9e003f94c217303dd160);
        vk.gate_setup_commitments[0] = PairingsBn254.new_g1(
            0x0ece437fd64391e5ae36341ebbe444a88f82ce028c7b0c50a70515c48505d583,
            0x15b056e44b2941e1aa776ea0103b34175c447424c381b349eb67e8ecf11a4259
        );
        vk.gate_setup_commitments[1] = PairingsBn254.new_g1(
            0x167344fe50565c45b6659e0aaf8caf574c909178c06a29f26482b71052809480,
            0x2eed8696a1ca301f7600ac0e7a9601c70ff1b6648ee2f2e5be96a0d1b7626cdc
        );
        vk.gate_setup_commitments[2] = PairingsBn254.new_g1(
            0x294144e65fd1bc5aa755e39b9af0c61cbabe142fd2061e81f51ca38849dbe9bc,
            0x080bae29b87d1b007b05e08e551106da65adf0638466e8d558922e0b53fbbe15
        );
        vk.gate_setup_commitments[3] = PairingsBn254.new_g1(
            0x2c571bbdf386ebb50475fe0e6651ada6ae4a4c6dea31df75e484e4b3c8abcb67,
            0x138325edb0f2a0e85d85006cfa8d9d395c44fe50dea61a173d8bb6ad52c89b17
        );
        vk.gate_setup_commitments[4] = PairingsBn254.new_g1(
            0x2c62bc7d31128836666b97f55c12cfa8c564a886ff79421e97843bd205eeca61,
            0x2d9b9a225c4a937a947ddde8a679f2d875983853b153847f6c3831116ac880f1
        );
        vk.gate_setup_commitments[5] = PairingsBn254.new_g1(
            0x1e4bc284c7b52928d2666c9bf58c0a33c398fa754e3379697548fe423dfdb6b2,
            0x29420b7796144068342b60cfbfdad14a269d0ea1dd2f10a283bdcf93224ebdf4
        );
        vk.gate_setup_commitments[6] = PairingsBn254.new_g1(
            0x21bf86d63e11e165f24acfa451f989f6020f744a1c141d60fa76512d1b950ab0,
            0x007183abc01c3775d669a191dd1cc773e7be98064a09fd6eeb189483640015c8
        );

        vk.gate_selector_commitments[0] = PairingsBn254.new_g1(
            0x2c0da680ac8c87196a2ac9a41cc3eb908fe3fc039befa4924372ec8e8e2c9130,
            0x19c4065926d0637e3679ba54f1e1fbef7fc281ae175f65fd31f2507a19a0191a
        );
        vk.gate_selector_commitments[1] = PairingsBn254.new_g1(
            0x1cc441b5c21afd0bb9443f1270f0d6bf6d998404cb4e9af2acb9fd956944cee1,
            0x2a9ad7c26cd91e0b036a8d7d7f834098dcc71182499211ff927f252ba80d4b79
        );

        vk.copy_permutation_commitments[0] = PairingsBn254.new_g1(
            0x1b0d7e66bd42ffda6b881587fbda7844e9e78e94501f00b0831b37dc7abe9333,
            0x2e3b09086eae2e76834b07bbc86bc87fcff70d81061d592560222de54b693468
        );
        vk.copy_permutation_commitments[1] = PairingsBn254.new_g1(
            0x01508d42a521990060a61c06cddb6d62848f05bd8fe1b862c85fa741e10eb626,
            0x21e91770d830236a90a07425c9eb948a0ef8f85fa1fa2bfc359437c2958a9cd9
        );
        vk.copy_permutation_commitments[2] = PairingsBn254.new_g1(
            0x278e67050c3b2e32c6d67128e04c2fbd994b1e29be94ae27c6c8cd72e8e840e6,
            0x01cc853d48f2d2bc5f2b458de80466aac15613a4bb385d9fab37daafbeafdf10
        );
        vk.copy_permutation_commitments[3] = PairingsBn254.new_g1(
            0x20d89420786da547e20b3c9f571b94c66d568576b1dfd77c686464951d2a2b6b,
            0x12ffc3dfd82e1df5b13df512833ee73b4f77ba227963e6ea1d0184ed63418449
        );

        vk.copy_permutation_non_residues[0] = PairingsBn254.new_fr(
            0x0000000000000000000000000000000000000000000000000000000000000005
        );
        vk.copy_permutation_non_residues[1] = PairingsBn254.new_fr(
            0x0000000000000000000000000000000000000000000000000000000000000007
        );
        vk.copy_permutation_non_residues[2] = PairingsBn254.new_fr(
            0x000000000000000000000000000000000000000000000000000000000000000a
        );

        vk.g2_x = PairingsBn254.new_g2(
            [0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1,
             0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0],
            [0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4,
             0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55]
        );
    }


}
