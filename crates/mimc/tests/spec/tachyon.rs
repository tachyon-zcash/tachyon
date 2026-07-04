use pasta_curves::Fp;

use super::*;

/// Shared cipher inputs `(keys, input)`; each module runs them against its own
/// spec. A single-element `keys` slice is the §2.1 cipher, several keys the
/// §5.2 cyclic variant. `-1` and `-2` are the field elements `p - 1` and
/// `p - 2`.
const CIPHER_INPUTS: &[(&[Fp], Fp)] = &[
    (
        &[Fp::from_raw([
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ])],
        Fp::from_raw([
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]),
    ),
    (
        &[Fp::from_raw([
            0x0000_0000_0000_0001,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ])],
        Fp::from_raw([
            0x0000_0000_0000_0002,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]),
    ),
    (
        &[Fp::from_raw([
            0x992d_30ed_0000_0000,
            0x2246_98fc_094c_f91b,
            0x0000_0000_0000_0000,
            0x4000_0000_0000_0000,
        ])],
        Fp::from_raw([
            0x992d_30ec_ffff_ffff,
            0x2246_98fc_094c_f91b,
            0x0000_0000_0000_0000,
            0x4000_0000_0000_0000,
        ]),
    ),
    (
        &[
            Fp::from_raw([
                0x0000_0000_0000_0001,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
            Fp::from_raw([
                0x0000_0000_0000_0002,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
        ],
        Fp::from_raw([
            0x0000_0000_0000_0003,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]),
    ),
    (
        &[
            Fp::from_raw([
                0x0000_0000_0000_0001,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
            Fp::from_raw([
                0x0000_0000_0000_0002,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
            Fp::from_raw([
                0x0000_0000_0000_0003,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
        ],
        Fp::from_raw([
            0x0000_0000_0000_0004,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
        ]),
    ),
];

mod tachyon_32 {
    use zcash_mimc::spec::tachyon::TachyonP5R32;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R32, Fp, 5, 32>(&[
            (
                1,
                Fp::from_raw([
                    0x6983_504b_3dbc_2b22,
                    0x1d3b_0898_7039_c175,
                    0xd5bc_01c0_e8d5_94f6,
                    0x2267_c77e_4561_9970,
                ]),
            ),
            (
                5,
                Fp::from_raw([
                    0x2480_efb0_8adf_28ad,
                    0x514e_36d1_5bb2_cc3d,
                    0x2901_1e6e_7392_afca,
                    0x051e_df43_c24f_d2c7,
                ]),
            ),
            (
                31,
                Fp::from_raw([
                    0xca28_1a4d_9bcc_4fac,
                    0x5aa7_f8d1_96fc_0732,
                    0x1e53_ad9f_cdb2_b774,
                    0x15c7_23cf_4aee_1c67,
                ]),
            ),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R32, Fp, 5, 32>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0x0a1e_30a7_ca75_d2ae,
                    0xb18c_87e2_9316_919f,
                    0xc868_ba65_cc93_2abb,
                    0x3060_f007_b514_f606,
                ]),
                Fp::from_raw([
                    0x641c_f56f_3438_fee7,
                    0x527f_abaf_7f80_73ad,
                    0x1355_e36b_3ab8_4dc6,
                    0x3e0a_008c_8319_5448,
                ]),
                Fp::from_raw([
                    0x2d8c_b91d_6f42_f5e3,
                    0x8485_d61f_e7c6_e8b1,
                    0xdb52_153e_55a5_c2af,
                    0x2e90_87e0_8858_0195,
                ]),
                Fp::from_raw([
                    0xefc4_a748_b75d_f80b,
                    0xadc7_b081_82f2_e515,
                    0xc4a6_8166_ea28_2b1b,
                    0x0cd2_a91c_b37c_735e,
                ]),
                Fp::from_raw([
                    0x5b0e_20de_c3d6_8cca,
                    0xd204_373a_3937_6604,
                    0x71db_5dc7_2bc3_f19b,
                    0x209a_335a_a79c_d0d4,
                ]),
            ],
        );
    }
}

mod tachyon_64 {
    use zcash_mimc::spec::tachyon::TachyonP5R64;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R64, Fp, 5, 64>(&[
            (
                1,
                Fp::from_raw([
                    0x094d_1825_2871_f3ee,
                    0x9838_6ebe_9cc2_f067,
                    0x56ae_910d_412a_5915,
                    0x1864_d848_98a8_fc70,
                ]),
            ),
            (
                5,
                Fp::from_raw([
                    0x4e5a_6394_9b2e_6e57,
                    0x9f04_6294_2fa2_da23,
                    0x9a0b_b762_e636_4d7c,
                    0x2445_b0a2_f5fa_44e3,
                ]),
            ),
            (
                63,
                Fp::from_raw([
                    0x8471_af86_0a8c_d582,
                    0x3e5d_1504_356c_b5a6,
                    0xcad8_da78_5b7e_d10d,
                    0x3f51_4957_78d1_c78b,
                ]),
            ),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R64, Fp, 5, 64>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0x0de4_2c9e_bc89_a1ea,
                    0x77df_d24c_c45b_1352,
                    0x30c1_9033_7a14_c8d6,
                    0x1c7a_0b19_0d17_a34d,
                ]),
                Fp::from_raw([
                    0x1f7a_d53f_7e9a_252a,
                    0x9d89_414a_1941_7666,
                    0x64e7_8bab_943f_d83d,
                    0x10fd_4ffc_9092_be76,
                ]),
                Fp::from_raw([
                    0xdf94_2108_9afd_e488,
                    0x0b31_86a7_f883_0da2,
                    0xc9ef_2c76_155c_624f,
                    0x2b4a_4284_1fb2_1642,
                ]),
                Fp::from_raw([
                    0x2665_9839_fc69_846e,
                    0x0701_2dc4_166e_3df8,
                    0x87ff_294a_3d0a_eb90,
                    0x09cc_44e9_fba0_d8d8,
                ]),
                Fp::from_raw([
                    0x53e8_5c44_1361_0fa7,
                    0x8b12_c0fc_3dc1_ed12,
                    0x973a_8358_9753_147c,
                    0x2631_5900_3c9e_1633,
                ]),
            ],
        );
    }
}

mod tachyon_128 {
    use zcash_mimc::spec::tachyon::TachyonP5R128;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R128, Fp, 5, 128>(&[
            (
                1,
                Fp::from_raw([
                    0x8798_1234_076e_01c7,
                    0x8514_cae3_caba_1445,
                    0x2b8f_7679_6940_ca85,
                    0x0872_8eea_48a4_bd3a,
                ]),
            ),
            (
                5,
                Fp::from_raw([
                    0x4733_7c7c_509e_1fcb,
                    0x7c91_59c2_95ee_196d,
                    0x03ba_0ec6_90f7_2858,
                    0x06a6_4ffb_b510_2b36,
                ]),
            ),
            (
                127,
                Fp::from_raw([
                    0x34d9_7ef3_e2c5_61b8,
                    0x3e01_32e5_6679_2b24,
                    0xeaa6_f165_dc50_5350,
                    0x21d6_0e47_d7fc_d232,
                ]),
            ),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R128, Fp, 5, 128>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0x168a_8869_a64a_3f56,
                    0x9abb_a153_0323_48a5,
                    0x8a81_5b88_ae84_682b,
                    0x19ea_0cd6_3752_1336,
                ]),
                Fp::from_raw([
                    0x8826_3ebe_1621_b65c,
                    0xc3be_22d0_b8cc_711b,
                    0x6841_4d6b_340e_3a37,
                    0x1a77_946f_fa00_7c9f,
                ]),
                Fp::from_raw([
                    0x5690_d773_3915_08fc,
                    0x3604_03a2_4343_ee26,
                    0x446a_a521_aaa4_5e6b,
                    0x205f_8451_7a1b_23ad,
                ]),
                Fp::from_raw([
                    0x74a6_30c6_0077_b420,
                    0x3552_a55f_e517_99cb,
                    0xf0b8_c957_d7e7_9ee5,
                    0x0755_5729_a410_a2e8,
                ]),
                Fp::from_raw([
                    0x2a6e_32df_db86_2445,
                    0x5fa2_031d_e6b1_6e8a,
                    0xfba0_cec3_3276_2174,
                    0x0e5d_38f1_5f25_0823,
                ]),
            ],
        );
    }
}

mod tachyon_8192 {
    use zcash_mimc::spec::tachyon::TachyonP5R8192;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R8192, Fp, 5, 8192>(&[
            (
                1,
                Fp::from_raw([
                    0x93b2_5b35_f211_f932,
                    0x493a_ed9c_18a3_1a78,
                    0xff85_f7a1_6cd1_3edd,
                    0x1e0b_9b47_8f59_bf41,
                ]),
            ),
            (
                5,
                Fp::from_raw([
                    0x4cfa_35b9_3b76_c949,
                    0x4d72_4f1d_d2f9_326c,
                    0x35e1_bd68_2c41_c89e,
                    0x0c24_9b2c_00bd_f96d,
                ]),
            ),
            (
                63,
                Fp::from_raw([
                    0xf177_5ae7_34e6_621a,
                    0xa157_b1c7_9d38_02a8,
                    0x80ba_5de2_df5a_fca1,
                    0x3777_69fd_b717_e566,
                ]),
            ),
            (
                8191,
                Fp::from_raw([
                    0xf247_baef_0b70_a072,
                    0x2dad_cc75_c440_5999,
                    0x8f35_b569_9723_53fe,
                    0x129d_2dd6_02a1_f711,
                ]),
            ),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R8192, Fp, 5, 8192>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0xc801_b3a8_75c9_cf49,
                    0x0565_5276_da81_3af2,
                    0x74f8_69aa_7b83_f967,
                    0x0edb_a58a_b47d_74d3,
                ]),
                Fp::from_raw([
                    0x1f0c_1de7_dd40_f21d,
                    0xf7ee_dc47_ad81_4a97,
                    0x49d6_504e_0513_bfc8,
                    0x3d33_6836_90f4_fc16,
                ]),
                Fp::from_raw([
                    0xed6c_4e3c_53d3_a92f,
                    0xce62_81b6_43de_423d,
                    0xc45d_7306_235d_e1da,
                    0x1822_88f9_46db_d7ef,
                ]),
                Fp::from_raw([
                    0x4f5a_39e1_14ee_cdb7,
                    0xa90e_f6d5_0f2f_da55,
                    0xb6b0_651b_2d4d_a9fa,
                    0x18ca_9533_250e_5696,
                ]),
                Fp::from_raw([
                    0x0296_75ee_abd7_cea6,
                    0x1675_cc36_93f4_8ca7,
                    0x7f4d_b9b1_09bb_5f9f,
                    0x34cb_fd7d_78ca_c566,
                ]),
            ],
        );
    }
}
