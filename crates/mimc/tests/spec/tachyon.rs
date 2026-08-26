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

mod tachyon_64 {
    use zcash_mimc::specs::tachyon::TachyonP5R64;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R64, 64>(&[
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
        check_encryptions::<TachyonP5R64, 64>(
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
