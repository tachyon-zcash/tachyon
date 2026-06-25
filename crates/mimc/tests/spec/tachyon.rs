use pasta_curves::Fp;

use super::*;

const EXPECTED_C1: Fp = Fp::from_raw([
    0xc772_90a6_3e7a_d8b9,
    0xc235_b3ac_cbef_23f6,
    0x4a0e_38e1_66f2_9757,
    0x145f_cac0_7566_b9ff,
]);

const EXPECTED_C5: Fp = Fp::from_raw([
    0x9058_fdbd_a0ab_27ee,
    0xab37_2b90_6793_09c4,
    0xedea_5733_1021_8d39,
    0x3e64_fad0_7af6_5c79,
]);

const EXPECTED_C63: Fp = Fp::from_raw([
    0xdc93_c5bd_fe42_f11f,
    0xe711_66f7_5380_68a2,
    0x3fd2_8b7c_965c_cf2d,
    0x149f_f4bc_ecab_5e32,
]);

const EXPECTED_C8191: Fp = Fp::from_raw([
    0x26ed_b91a_0932_1064,
    0x982b_73c3_b191_bfe7,
    0xe647_3451_7bf3_18bc,
    0x219d_94d9_54f9_638b,
]);

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
    use zcash_mimc::spec::tachyon::TachyonP5R64;

    use super::*;

    #[test]
    fn pinned_round_constants() {
        check_constants::<TachyonP5R64, Fp, 5, 64>(&[
            (1, EXPECTED_C1),
            (5, EXPECTED_C5),
            (63, EXPECTED_C63),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R64, Fp, 5, 64>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0x4e98_3435_226c_17aa,
                    0x1666_4366_6dc2_211b,
                    0x8342_eb80_6578_4f80,
                    0x3abc_9c58_bd9e_3e49,
                ]),
                Fp::from_raw([
                    0x523a_8c8a_cdf3_55ee,
                    0x7871_1bb7_6617_b464,
                    0xc3ac_90a9_e977_a40b,
                    0x07b8_9754_45f8_4884,
                ]),
                Fp::from_raw([
                    0x19e4_4443_51d1_4e9b,
                    0x037b_f013_3cc6_1773,
                    0x2c39_dadf_2982_1bcd,
                    0x1957_f633_9a41_fdbb,
                ]),
                Fp::from_raw([
                    0x0ba2_ebe6_538e_5036,
                    0xb950_b7cd_14ab_44e0,
                    0xc234_a0c4_b790_1b62,
                    0x3114_db1e_d215_2ecb,
                ]),
                Fp::from_raw([
                    0x3a75_f830_61ca_ab48,
                    0x6ea7_7381_021f_53eb,
                    0xc4dd_067a_bc81_19ed,
                    0x0ed3_aa1c_6282_d870,
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
            (1, EXPECTED_C1),
            (5, EXPECTED_C5),
            (63, EXPECTED_C63),
            (8191, EXPECTED_C8191),
        ]);
    }

    #[test]
    fn pinned_encryption_outputs() {
        check_encryptions::<TachyonP5R8192, Fp, 5, 8192>(
            CIPHER_INPUTS,
            &[
                Fp::from_raw([
                    0xb1e0_0e5e_3472_4a51,
                    0xe777_ce56_0ada_f16d,
                    0xb905_7a21_2f6a_ce0f,
                    0x01d5_337f_22fd_95c2,
                ]),
                Fp::from_raw([
                    0xf889_d714_7e34_6971,
                    0xa76f_9279_5384_1abe,
                    0x5f19_0b71_30e3_4214,
                    0x22b9_1581_7673_e836,
                ]),
                Fp::from_raw([
                    0x948f_3da7_373f_b276,
                    0xf803_626a_881b_54a9,
                    0x9dcf_cae4_0b26_e5df,
                    0x38e3_f121_174f_2c9e,
                ]),
                Fp::from_raw([
                    0x097f_0dca_5ca6_e098,
                    0x0122_3fc6_4d22_759c,
                    0x0292_008c_42c6_3c7f,
                    0x35fb_03ed_b915_1d97,
                ]),
                Fp::from_raw([
                    0xd84a_cd95_dac0_480b,
                    0x6150_e780_0efb_11e4,
                    0x23ff_1a57_e2e5_6388,
                    0x0692_87e5_1885_b0c4,
                ]),
            ],
        );
    }
}
