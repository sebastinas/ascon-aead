use ascon::{
    self,
    aead::{Aead, NewAead, Payload},
};
use hex;
use std::collections::HashMap;
use std::include_str;

struct TestVector {
    // count: u32,
    key: ascon::Key,
    nonce: ascon::Nonce,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl TestVector {
    fn new(
        _: &str,
        key: &str,
        nonce: &str,
        plaintext: &str,
        associated_data: &str,
        ciphertext: &str,
    ) -> Self {
        Self {
            // count: count.parse::<u32>().unwrap(),
            key: *ascon::Key::from_slice(hex::decode(key).unwrap().as_slice()),
            nonce: *ascon::Nonce::from_slice(hex::decode(nonce).unwrap().as_slice()),
            plaintext: hex::decode(plaintext).unwrap(),
            associated_data: hex::decode(associated_data).unwrap(),
            ciphertext: hex::decode(ciphertext).unwrap(),
        }
    }
}

/*
fn run_tv_core(tv: &TestVector) {
    let mut core = ascon::Core::<ascon::Parameters128>::new(&tv.key, &tv.nonce);
    let mut ciphertext: Vec<u8> = Vec::new();
    ciphertext.resize(tv.plaintext.len(), 0);
    let tag = core.encrypt(
        &mut ciphertext.as_mut_slice(),
        &tv.plaintext,
        &tv.associated_data,
    );

    let mut core_decrypt = ascon::Core::<ascon::Parameters128>::new(&tv.key, &tv.nonce);
    let mut plaintext: Vec<u8> = Vec::new();
    plaintext.resize(tv.plaintext.len(), 0);
    core_decrypt
        .decrypt(
            &mut plaintext.as_mut_slice(),
            &ciphertext,
            &tv.associated_data,
            &tag,
        )
        .unwrap();

    ciphertext.extend_from_slice(tag.as_slice());
    assert_eq!(ciphertext, tv.ciphertext);
    assert_eq!(plaintext, tv.plaintext);
}
*/

fn run_tv_aead(tv: TestVector) {
    let core = ascon::Ascon::new(&tv.key);
    let ciphertext = core
        .encrypt(
            &tv.nonce,
            Payload {
                msg: &tv.plaintext,
                aad: &tv.associated_data,
            },
        )
        .unwrap();

    let plaintext = core
        .decrypt(
            &tv.nonce,
            Payload {
                msg: &tv.ciphertext,
                aad: &tv.associated_data,
            },
        )
        .unwrap();

    assert_eq!(ciphertext, tv.ciphertext);
    assert_eq!(plaintext, tv.plaintext);
}

fn run_tv(tv: TestVector) {
    run_tv_aead(tv);
}

fn parse_tv(tvs: &str) -> TestVector {
    let mut fields: HashMap<String, String> = HashMap::new();

    for line in tvs.lines() {
        let mut values = line.split(" = ");
        fields.insert(
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        );
    }

    TestVector::new(
        &fields["Count"],
        &fields["Key"],
        &fields["Nonce"],
        &fields["PT"],
        &fields["AD"],
        &fields["CT"],
    )
}

#[test]
fn tv_1() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1.txt")));
}

#[test]
fn tv_2() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-2.txt")));
}

#[test]
fn tv_3() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-3.txt")));
}

#[test]
fn tv_4() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-4.txt")));
}

#[test]
fn tv_5() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-5.txt")));
}

#[test]
fn tv_6() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-6.txt")));
}

#[test]
fn tv_7() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-7.txt")));
}

#[test]
fn tv_8() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-8.txt")));
}

#[test]
fn tv_9() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-9.txt")));
}

#[test]
fn tv_10() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-10.txt")));
}

#[test]
fn tv_11() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-11.txt")));
}

#[test]
fn tv_12() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-12.txt")));
}

#[test]
fn tv_13() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-13.txt")));
}

#[test]
fn tv_14() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-14.txt")));
}

#[test]
fn tv_15() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-15.txt")));
}

#[test]
fn tv_16() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-16.txt")));
}

#[test]
fn tv_17() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-17.txt")));
}

#[test]
fn tv_18() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-18.txt")));
}

#[test]
fn tv_19() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-19.txt")));
}

#[test]
fn tv_20() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-20.txt")));
}

#[test]
fn tv_21() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-21.txt")));
}

#[test]
fn tv_22() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-22.txt")));
}

#[test]
fn tv_23() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-23.txt")));
}

#[test]
fn tv_24() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-24.txt")));
}

#[test]
fn tv_25() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-25.txt")));
}

#[test]
fn tv_26() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-26.txt")));
}

#[test]
fn tv_27() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-27.txt")));
}

#[test]
fn tv_28() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-28.txt")));
}

#[test]
fn tv_29() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-29.txt")));
}

#[test]
fn tv_30() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-30.txt")));
}

#[test]
fn tv_31() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-31.txt")));
}

#[test]
fn tv_32() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-32.txt")));
}

#[test]
fn tv_33() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-33.txt")));
}

#[test]
fn tv_34() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-34.txt")));
}

#[test]
fn tv_35() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-35.txt")));
}

#[test]
fn tv_36() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-36.txt")));
}

#[test]
fn tv_37() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-37.txt")));
}

#[test]
fn tv_38() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-38.txt")));
}

#[test]
fn tv_39() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-39.txt")));
}

#[test]
fn tv_40() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-40.txt")));
}

#[test]
fn tv_41() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-41.txt")));
}

#[test]
fn tv_42() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-42.txt")));
}

#[test]
fn tv_43() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-43.txt")));
}

#[test]
fn tv_44() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-44.txt")));
}

#[test]
fn tv_45() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-45.txt")));
}

#[test]
fn tv_46() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-46.txt")));
}

#[test]
fn tv_47() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-47.txt")));
}

#[test]
fn tv_48() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-48.txt")));
}

#[test]
fn tv_49() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-49.txt")));
}

#[test]
fn tv_50() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-50.txt")));
}

#[test]
fn tv_51() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-51.txt")));
}

#[test]
fn tv_52() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-52.txt")));
}

#[test]
fn tv_53() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-53.txt")));
}

#[test]
fn tv_54() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-54.txt")));
}

#[test]
fn tv_55() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-55.txt")));
}

#[test]
fn tv_56() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-56.txt")));
}

#[test]
fn tv_57() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-57.txt")));
}

#[test]
fn tv_58() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-58.txt")));
}

#[test]
fn tv_59() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-59.txt")));
}

#[test]
fn tv_60() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-60.txt")));
}

#[test]
fn tv_61() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-61.txt")));
}

#[test]
fn tv_62() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-62.txt")));
}

#[test]
fn tv_63() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-63.txt")));
}

#[test]
fn tv_64() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-64.txt")));
}

#[test]
fn tv_65() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-65.txt")));
}

#[test]
fn tv_66() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-66.txt")));
}

#[test]
fn tv_67() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-67.txt")));
}

#[test]
fn tv_68() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-68.txt")));
}

#[test]
fn tv_69() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-69.txt")));
}

#[test]
fn tv_70() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-70.txt")));
}

#[test]
fn tv_71() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-71.txt")));
}

#[test]
fn tv_72() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-72.txt")));
}

#[test]
fn tv_73() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-73.txt")));
}

#[test]
fn tv_74() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-74.txt")));
}

#[test]
fn tv_75() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-75.txt")));
}

#[test]
fn tv_76() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-76.txt")));
}

#[test]
fn tv_77() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-77.txt")));
}

#[test]
fn tv_78() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-78.txt")));
}

#[test]
fn tv_79() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-79.txt")));
}

#[test]
fn tv_80() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-80.txt")));
}

#[test]
fn tv_81() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-81.txt")));
}

#[test]
fn tv_82() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-82.txt")));
}

#[test]
fn tv_83() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-83.txt")));
}

#[test]
fn tv_84() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-84.txt")));
}

#[test]
fn tv_85() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-85.txt")));
}

#[test]
fn tv_86() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-86.txt")));
}

#[test]
fn tv_87() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-87.txt")));
}

#[test]
fn tv_88() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-88.txt")));
}

#[test]
fn tv_89() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-89.txt")));
}

#[test]
fn tv_90() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-90.txt")));
}

#[test]
fn tv_91() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-91.txt")));
}

#[test]
fn tv_92() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-92.txt")));
}

#[test]
fn tv_93() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-93.txt")));
}

#[test]
fn tv_94() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-94.txt")));
}

#[test]
fn tv_95() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-95.txt")));
}

#[test]
fn tv_96() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-96.txt")));
}

#[test]
fn tv_97() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-97.txt")));
}

#[test]
fn tv_98() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-98.txt")));
}

#[test]
fn tv_99() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-99.txt")));
}

#[test]
fn tv_100() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-100.txt")));
}

#[test]
fn tv_101() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-101.txt")));
}

#[test]
fn tv_102() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-102.txt")));
}

#[test]
fn tv_103() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-103.txt")));
}

#[test]
fn tv_104() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-104.txt")));
}

#[test]
fn tv_105() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-105.txt")));
}

#[test]
fn tv_106() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-106.txt")));
}

#[test]
fn tv_107() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-107.txt")));
}

#[test]
fn tv_108() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-108.txt")));
}

#[test]
fn tv_109() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-109.txt")));
}

#[test]
fn tv_110() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-110.txt")));
}

#[test]
fn tv_111() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-111.txt")));
}

#[test]
fn tv_112() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-112.txt")));
}

#[test]
fn tv_113() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-113.txt")));
}

#[test]
fn tv_114() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-114.txt")));
}

#[test]
fn tv_115() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-115.txt")));
}

#[test]
fn tv_116() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-116.txt")));
}

#[test]
fn tv_117() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-117.txt")));
}

#[test]
fn tv_118() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-118.txt")));
}

#[test]
fn tv_119() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-119.txt")));
}

#[test]
fn tv_120() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-120.txt")));
}

#[test]
fn tv_121() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-121.txt")));
}

#[test]
fn tv_122() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-122.txt")));
}

#[test]
fn tv_123() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-123.txt")));
}

#[test]
fn tv_124() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-124.txt")));
}

#[test]
fn tv_125() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-125.txt")));
}

#[test]
fn tv_126() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-126.txt")));
}

#[test]
fn tv_127() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-127.txt")));
}

#[test]
fn tv_128() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-128.txt")));
}

#[test]
fn tv_129() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-129.txt")));
}

#[test]
fn tv_130() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-130.txt")));
}

#[test]
fn tv_131() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-131.txt")));
}

#[test]
fn tv_132() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-132.txt")));
}

#[test]
fn tv_133() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-133.txt")));
}

#[test]
fn tv_134() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-134.txt")));
}

#[test]
fn tv_135() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-135.txt")));
}

#[test]
fn tv_136() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-136.txt")));
}

#[test]
fn tv_137() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-137.txt")));
}

#[test]
fn tv_138() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-138.txt")));
}

#[test]
fn tv_139() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-139.txt")));
}

#[test]
fn tv_140() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-140.txt")));
}

#[test]
fn tv_141() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-141.txt")));
}

#[test]
fn tv_142() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-142.txt")));
}

#[test]
fn tv_143() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-143.txt")));
}

#[test]
fn tv_144() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-144.txt")));
}

#[test]
fn tv_145() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-145.txt")));
}

#[test]
fn tv_146() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-146.txt")));
}

#[test]
fn tv_147() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-147.txt")));
}

#[test]
fn tv_148() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-148.txt")));
}

#[test]
fn tv_149() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-149.txt")));
}

#[test]
fn tv_150() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-150.txt")));
}

#[test]
fn tv_151() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-151.txt")));
}

#[test]
fn tv_152() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-152.txt")));
}

#[test]
fn tv_153() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-153.txt")));
}

#[test]
fn tv_154() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-154.txt")));
}

#[test]
fn tv_155() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-155.txt")));
}

#[test]
fn tv_156() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-156.txt")));
}

#[test]
fn tv_157() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-157.txt")));
}

#[test]
fn tv_158() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-158.txt")));
}

#[test]
fn tv_159() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-159.txt")));
}

#[test]
fn tv_160() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-160.txt")));
}

#[test]
fn tv_161() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-161.txt")));
}

#[test]
fn tv_162() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-162.txt")));
}

#[test]
fn tv_163() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-163.txt")));
}

#[test]
fn tv_164() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-164.txt")));
}

#[test]
fn tv_165() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-165.txt")));
}

#[test]
fn tv_166() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-166.txt")));
}

#[test]
fn tv_167() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-167.txt")));
}

#[test]
fn tv_168() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-168.txt")));
}

#[test]
fn tv_169() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-169.txt")));
}

#[test]
fn tv_170() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-170.txt")));
}

#[test]
fn tv_171() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-171.txt")));
}

#[test]
fn tv_172() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-172.txt")));
}

#[test]
fn tv_173() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-173.txt")));
}

#[test]
fn tv_174() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-174.txt")));
}

#[test]
fn tv_175() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-175.txt")));
}

#[test]
fn tv_176() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-176.txt")));
}

#[test]
fn tv_177() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-177.txt")));
}

#[test]
fn tv_178() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-178.txt")));
}

#[test]
fn tv_179() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-179.txt")));
}

#[test]
fn tv_180() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-180.txt")));
}

#[test]
fn tv_181() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-181.txt")));
}

#[test]
fn tv_182() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-182.txt")));
}

#[test]
fn tv_183() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-183.txt")));
}

#[test]
fn tv_184() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-184.txt")));
}

#[test]
fn tv_185() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-185.txt")));
}

#[test]
fn tv_186() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-186.txt")));
}

#[test]
fn tv_187() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-187.txt")));
}

#[test]
fn tv_188() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-188.txt")));
}

#[test]
fn tv_189() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-189.txt")));
}

#[test]
fn tv_190() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-190.txt")));
}

#[test]
fn tv_191() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-191.txt")));
}

#[test]
fn tv_192() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-192.txt")));
}

#[test]
fn tv_193() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-193.txt")));
}

#[test]
fn tv_194() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-194.txt")));
}

#[test]
fn tv_195() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-195.txt")));
}

#[test]
fn tv_196() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-196.txt")));
}

#[test]
fn tv_197() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-197.txt")));
}

#[test]
fn tv_198() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-198.txt")));
}

#[test]
fn tv_199() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-199.txt")));
}

#[test]
fn tv_200() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-200.txt")));
}

#[test]
fn tv_201() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-201.txt")));
}

#[test]
fn tv_202() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-202.txt")));
}

#[test]
fn tv_203() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-203.txt")));
}

#[test]
fn tv_204() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-204.txt")));
}

#[test]
fn tv_205() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-205.txt")));
}

#[test]
fn tv_206() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-206.txt")));
}

#[test]
fn tv_207() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-207.txt")));
}

#[test]
fn tv_208() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-208.txt")));
}

#[test]
fn tv_209() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-209.txt")));
}

#[test]
fn tv_210() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-210.txt")));
}

#[test]
fn tv_211() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-211.txt")));
}

#[test]
fn tv_212() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-212.txt")));
}

#[test]
fn tv_213() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-213.txt")));
}

#[test]
fn tv_214() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-214.txt")));
}

#[test]
fn tv_215() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-215.txt")));
}

#[test]
fn tv_216() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-216.txt")));
}

#[test]
fn tv_217() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-217.txt")));
}

#[test]
fn tv_218() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-218.txt")));
}

#[test]
fn tv_219() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-219.txt")));
}

#[test]
fn tv_220() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-220.txt")));
}

#[test]
fn tv_221() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-221.txt")));
}

#[test]
fn tv_222() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-222.txt")));
}

#[test]
fn tv_223() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-223.txt")));
}

#[test]
fn tv_224() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-224.txt")));
}

#[test]
fn tv_225() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-225.txt")));
}

#[test]
fn tv_226() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-226.txt")));
}

#[test]
fn tv_227() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-227.txt")));
}

#[test]
fn tv_228() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-228.txt")));
}

#[test]
fn tv_229() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-229.txt")));
}

#[test]
fn tv_230() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-230.txt")));
}

#[test]
fn tv_231() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-231.txt")));
}

#[test]
fn tv_232() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-232.txt")));
}

#[test]
fn tv_233() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-233.txt")));
}

#[test]
fn tv_234() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-234.txt")));
}

#[test]
fn tv_235() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-235.txt")));
}

#[test]
fn tv_236() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-236.txt")));
}

#[test]
fn tv_237() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-237.txt")));
}

#[test]
fn tv_238() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-238.txt")));
}

#[test]
fn tv_239() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-239.txt")));
}

#[test]
fn tv_240() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-240.txt")));
}

#[test]
fn tv_241() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-241.txt")));
}

#[test]
fn tv_242() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-242.txt")));
}

#[test]
fn tv_243() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-243.txt")));
}

#[test]
fn tv_244() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-244.txt")));
}

#[test]
fn tv_245() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-245.txt")));
}

#[test]
fn tv_246() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-246.txt")));
}

#[test]
fn tv_247() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-247.txt")));
}

#[test]
fn tv_248() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-248.txt")));
}

#[test]
fn tv_249() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-249.txt")));
}

#[test]
fn tv_250() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-250.txt")));
}

#[test]
fn tv_251() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-251.txt")));
}

#[test]
fn tv_252() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-252.txt")));
}

#[test]
fn tv_253() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-253.txt")));
}

#[test]
fn tv_254() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-254.txt")));
}

#[test]
fn tv_255() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-255.txt")));
}

#[test]
fn tv_256() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-256.txt")));
}

#[test]
fn tv_257() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-257.txt")));
}

#[test]
fn tv_258() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-258.txt")));
}

#[test]
fn tv_259() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-259.txt")));
}

#[test]
fn tv_260() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-260.txt")));
}

#[test]
fn tv_261() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-261.txt")));
}

#[test]
fn tv_262() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-262.txt")));
}

#[test]
fn tv_263() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-263.txt")));
}

#[test]
fn tv_264() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-264.txt")));
}

#[test]
fn tv_265() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-265.txt")));
}

#[test]
fn tv_266() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-266.txt")));
}

#[test]
fn tv_267() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-267.txt")));
}

#[test]
fn tv_268() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-268.txt")));
}

#[test]
fn tv_269() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-269.txt")));
}

#[test]
fn tv_270() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-270.txt")));
}

#[test]
fn tv_271() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-271.txt")));
}

#[test]
fn tv_272() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-272.txt")));
}

#[test]
fn tv_273() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-273.txt")));
}

#[test]
fn tv_274() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-274.txt")));
}

#[test]
fn tv_275() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-275.txt")));
}

#[test]
fn tv_276() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-276.txt")));
}

#[test]
fn tv_277() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-277.txt")));
}

#[test]
fn tv_278() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-278.txt")));
}

#[test]
fn tv_279() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-279.txt")));
}

#[test]
fn tv_280() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-280.txt")));
}

#[test]
fn tv_281() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-281.txt")));
}

#[test]
fn tv_282() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-282.txt")));
}

#[test]
fn tv_283() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-283.txt")));
}

#[test]
fn tv_284() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-284.txt")));
}

#[test]
fn tv_285() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-285.txt")));
}

#[test]
fn tv_286() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-286.txt")));
}

#[test]
fn tv_287() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-287.txt")));
}

#[test]
fn tv_288() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-288.txt")));
}

#[test]
fn tv_289() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-289.txt")));
}

#[test]
fn tv_290() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-290.txt")));
}

#[test]
fn tv_291() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-291.txt")));
}

#[test]
fn tv_292() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-292.txt")));
}

#[test]
fn tv_293() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-293.txt")));
}

#[test]
fn tv_294() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-294.txt")));
}

#[test]
fn tv_295() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-295.txt")));
}

#[test]
fn tv_296() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-296.txt")));
}

#[test]
fn tv_297() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-297.txt")));
}

#[test]
fn tv_298() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-298.txt")));
}

#[test]
fn tv_299() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-299.txt")));
}

#[test]
fn tv_300() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-300.txt")));
}

#[test]
fn tv_301() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-301.txt")));
}

#[test]
fn tv_302() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-302.txt")));
}

#[test]
fn tv_303() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-303.txt")));
}

#[test]
fn tv_304() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-304.txt")));
}

#[test]
fn tv_305() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-305.txt")));
}

#[test]
fn tv_306() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-306.txt")));
}

#[test]
fn tv_307() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-307.txt")));
}

#[test]
fn tv_308() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-308.txt")));
}

#[test]
fn tv_309() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-309.txt")));
}

#[test]
fn tv_310() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-310.txt")));
}

#[test]
fn tv_311() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-311.txt")));
}

#[test]
fn tv_312() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-312.txt")));
}

#[test]
fn tv_313() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-313.txt")));
}

#[test]
fn tv_314() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-314.txt")));
}

#[test]
fn tv_315() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-315.txt")));
}

#[test]
fn tv_316() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-316.txt")));
}

#[test]
fn tv_317() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-317.txt")));
}

#[test]
fn tv_318() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-318.txt")));
}

#[test]
fn tv_319() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-319.txt")));
}

#[test]
fn tv_320() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-320.txt")));
}

#[test]
fn tv_321() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-321.txt")));
}

#[test]
fn tv_322() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-322.txt")));
}

#[test]
fn tv_323() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-323.txt")));
}

#[test]
fn tv_324() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-324.txt")));
}

#[test]
fn tv_325() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-325.txt")));
}

#[test]
fn tv_326() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-326.txt")));
}

#[test]
fn tv_327() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-327.txt")));
}

#[test]
fn tv_328() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-328.txt")));
}

#[test]
fn tv_329() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-329.txt")));
}

#[test]
fn tv_330() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-330.txt")));
}

#[test]
fn tv_331() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-331.txt")));
}

#[test]
fn tv_332() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-332.txt")));
}

#[test]
fn tv_333() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-333.txt")));
}

#[test]
fn tv_334() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-334.txt")));
}

#[test]
fn tv_335() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-335.txt")));
}

#[test]
fn tv_336() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-336.txt")));
}

#[test]
fn tv_337() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-337.txt")));
}

#[test]
fn tv_338() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-338.txt")));
}

#[test]
fn tv_339() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-339.txt")));
}

#[test]
fn tv_340() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-340.txt")));
}

#[test]
fn tv_341() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-341.txt")));
}

#[test]
fn tv_342() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-342.txt")));
}

#[test]
fn tv_343() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-343.txt")));
}

#[test]
fn tv_344() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-344.txt")));
}

#[test]
fn tv_345() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-345.txt")));
}

#[test]
fn tv_346() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-346.txt")));
}

#[test]
fn tv_347() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-347.txt")));
}

#[test]
fn tv_348() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-348.txt")));
}

#[test]
fn tv_349() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-349.txt")));
}

#[test]
fn tv_350() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-350.txt")));
}

#[test]
fn tv_351() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-351.txt")));
}

#[test]
fn tv_352() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-352.txt")));
}

#[test]
fn tv_353() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-353.txt")));
}

#[test]
fn tv_354() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-354.txt")));
}

#[test]
fn tv_355() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-355.txt")));
}

#[test]
fn tv_356() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-356.txt")));
}

#[test]
fn tv_357() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-357.txt")));
}

#[test]
fn tv_358() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-358.txt")));
}

#[test]
fn tv_359() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-359.txt")));
}

#[test]
fn tv_360() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-360.txt")));
}

#[test]
fn tv_361() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-361.txt")));
}

#[test]
fn tv_362() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-362.txt")));
}

#[test]
fn tv_363() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-363.txt")));
}

#[test]
fn tv_364() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-364.txt")));
}

#[test]
fn tv_365() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-365.txt")));
}

#[test]
fn tv_366() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-366.txt")));
}

#[test]
fn tv_367() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-367.txt")));
}

#[test]
fn tv_368() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-368.txt")));
}

#[test]
fn tv_369() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-369.txt")));
}

#[test]
fn tv_370() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-370.txt")));
}

#[test]
fn tv_371() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-371.txt")));
}

#[test]
fn tv_372() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-372.txt")));
}

#[test]
fn tv_373() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-373.txt")));
}

#[test]
fn tv_374() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-374.txt")));
}

#[test]
fn tv_375() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-375.txt")));
}

#[test]
fn tv_376() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-376.txt")));
}

#[test]
fn tv_377() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-377.txt")));
}

#[test]
fn tv_378() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-378.txt")));
}

#[test]
fn tv_379() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-379.txt")));
}

#[test]
fn tv_380() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-380.txt")));
}

#[test]
fn tv_381() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-381.txt")));
}

#[test]
fn tv_382() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-382.txt")));
}

#[test]
fn tv_383() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-383.txt")));
}

#[test]
fn tv_384() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-384.txt")));
}

#[test]
fn tv_385() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-385.txt")));
}

#[test]
fn tv_386() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-386.txt")));
}

#[test]
fn tv_387() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-387.txt")));
}

#[test]
fn tv_388() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-388.txt")));
}

#[test]
fn tv_389() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-389.txt")));
}

#[test]
fn tv_390() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-390.txt")));
}

#[test]
fn tv_391() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-391.txt")));
}

#[test]
fn tv_392() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-392.txt")));
}

#[test]
fn tv_393() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-393.txt")));
}

#[test]
fn tv_394() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-394.txt")));
}

#[test]
fn tv_395() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-395.txt")));
}

#[test]
fn tv_396() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-396.txt")));
}

#[test]
fn tv_397() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-397.txt")));
}

#[test]
fn tv_398() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-398.txt")));
}

#[test]
fn tv_399() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-399.txt")));
}

#[test]
fn tv_400() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-400.txt")));
}

#[test]
fn tv_401() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-401.txt")));
}

#[test]
fn tv_402() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-402.txt")));
}

#[test]
fn tv_403() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-403.txt")));
}

#[test]
fn tv_404() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-404.txt")));
}

#[test]
fn tv_405() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-405.txt")));
}

#[test]
fn tv_406() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-406.txt")));
}

#[test]
fn tv_407() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-407.txt")));
}

#[test]
fn tv_408() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-408.txt")));
}

#[test]
fn tv_409() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-409.txt")));
}

#[test]
fn tv_410() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-410.txt")));
}

#[test]
fn tv_411() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-411.txt")));
}

#[test]
fn tv_412() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-412.txt")));
}

#[test]
fn tv_413() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-413.txt")));
}

#[test]
fn tv_414() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-414.txt")));
}

#[test]
fn tv_415() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-415.txt")));
}

#[test]
fn tv_416() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-416.txt")));
}

#[test]
fn tv_417() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-417.txt")));
}

#[test]
fn tv_418() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-418.txt")));
}

#[test]
fn tv_419() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-419.txt")));
}

#[test]
fn tv_420() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-420.txt")));
}

#[test]
fn tv_421() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-421.txt")));
}

#[test]
fn tv_422() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-422.txt")));
}

#[test]
fn tv_423() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-423.txt")));
}

#[test]
fn tv_424() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-424.txt")));
}

#[test]
fn tv_425() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-425.txt")));
}

#[test]
fn tv_426() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-426.txt")));
}

#[test]
fn tv_427() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-427.txt")));
}

#[test]
fn tv_428() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-428.txt")));
}

#[test]
fn tv_429() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-429.txt")));
}

#[test]
fn tv_430() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-430.txt")));
}

#[test]
fn tv_431() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-431.txt")));
}

#[test]
fn tv_432() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-432.txt")));
}

#[test]
fn tv_433() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-433.txt")));
}

#[test]
fn tv_434() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-434.txt")));
}

#[test]
fn tv_435() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-435.txt")));
}

#[test]
fn tv_436() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-436.txt")));
}

#[test]
fn tv_437() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-437.txt")));
}

#[test]
fn tv_438() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-438.txt")));
}

#[test]
fn tv_439() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-439.txt")));
}

#[test]
fn tv_440() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-440.txt")));
}

#[test]
fn tv_441() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-441.txt")));
}

#[test]
fn tv_442() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-442.txt")));
}

#[test]
fn tv_443() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-443.txt")));
}

#[test]
fn tv_444() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-444.txt")));
}

#[test]
fn tv_445() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-445.txt")));
}

#[test]
fn tv_446() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-446.txt")));
}

#[test]
fn tv_447() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-447.txt")));
}

#[test]
fn tv_448() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-448.txt")));
}

#[test]
fn tv_449() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-449.txt")));
}

#[test]
fn tv_450() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-450.txt")));
}

#[test]
fn tv_451() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-451.txt")));
}

#[test]
fn tv_452() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-452.txt")));
}

#[test]
fn tv_453() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-453.txt")));
}

#[test]
fn tv_454() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-454.txt")));
}

#[test]
fn tv_455() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-455.txt")));
}

#[test]
fn tv_456() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-456.txt")));
}

#[test]
fn tv_457() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-457.txt")));
}

#[test]
fn tv_458() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-458.txt")));
}

#[test]
fn tv_459() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-459.txt")));
}

#[test]
fn tv_460() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-460.txt")));
}

#[test]
fn tv_461() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-461.txt")));
}

#[test]
fn tv_462() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-462.txt")));
}

#[test]
fn tv_463() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-463.txt")));
}

#[test]
fn tv_464() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-464.txt")));
}

#[test]
fn tv_465() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-465.txt")));
}

#[test]
fn tv_466() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-466.txt")));
}

#[test]
fn tv_467() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-467.txt")));
}

#[test]
fn tv_468() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-468.txt")));
}

#[test]
fn tv_469() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-469.txt")));
}

#[test]
fn tv_470() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-470.txt")));
}

#[test]
fn tv_471() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-471.txt")));
}

#[test]
fn tv_472() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-472.txt")));
}

#[test]
fn tv_473() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-473.txt")));
}

#[test]
fn tv_474() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-474.txt")));
}

#[test]
fn tv_475() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-475.txt")));
}

#[test]
fn tv_476() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-476.txt")));
}

#[test]
fn tv_477() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-477.txt")));
}

#[test]
fn tv_478() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-478.txt")));
}

#[test]
fn tv_479() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-479.txt")));
}

#[test]
fn tv_480() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-480.txt")));
}

#[test]
fn tv_481() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-481.txt")));
}

#[test]
fn tv_482() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-482.txt")));
}

#[test]
fn tv_483() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-483.txt")));
}

#[test]
fn tv_484() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-484.txt")));
}

#[test]
fn tv_485() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-485.txt")));
}

#[test]
fn tv_486() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-486.txt")));
}

#[test]
fn tv_487() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-487.txt")));
}

#[test]
fn tv_488() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-488.txt")));
}

#[test]
fn tv_489() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-489.txt")));
}

#[test]
fn tv_490() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-490.txt")));
}

#[test]
fn tv_491() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-491.txt")));
}

#[test]
fn tv_492() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-492.txt")));
}

#[test]
fn tv_493() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-493.txt")));
}

#[test]
fn tv_494() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-494.txt")));
}

#[test]
fn tv_495() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-495.txt")));
}

#[test]
fn tv_496() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-496.txt")));
}

#[test]
fn tv_497() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-497.txt")));
}

#[test]
fn tv_498() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-498.txt")));
}

#[test]
fn tv_499() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-499.txt")));
}

#[test]
fn tv_500() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-500.txt")));
}

#[test]
fn tv_501() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-501.txt")));
}

#[test]
fn tv_502() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-502.txt")));
}

#[test]
fn tv_503() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-503.txt")));
}

#[test]
fn tv_504() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-504.txt")));
}

#[test]
fn tv_505() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-505.txt")));
}

#[test]
fn tv_506() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-506.txt")));
}

#[test]
fn tv_507() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-507.txt")));
}

#[test]
fn tv_508() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-508.txt")));
}

#[test]
fn tv_509() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-509.txt")));
}

#[test]
fn tv_510() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-510.txt")));
}

#[test]
fn tv_511() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-511.txt")));
}

#[test]
fn tv_512() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-512.txt")));
}

#[test]
fn tv_513() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-513.txt")));
}

#[test]
fn tv_514() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-514.txt")));
}

#[test]
fn tv_515() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-515.txt")));
}

#[test]
fn tv_516() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-516.txt")));
}

#[test]
fn tv_517() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-517.txt")));
}

#[test]
fn tv_518() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-518.txt")));
}

#[test]
fn tv_519() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-519.txt")));
}

#[test]
fn tv_520() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-520.txt")));
}

#[test]
fn tv_521() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-521.txt")));
}

#[test]
fn tv_522() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-522.txt")));
}

#[test]
fn tv_523() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-523.txt")));
}

#[test]
fn tv_524() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-524.txt")));
}

#[test]
fn tv_525() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-525.txt")));
}

#[test]
fn tv_526() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-526.txt")));
}

#[test]
fn tv_527() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-527.txt")));
}

#[test]
fn tv_528() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-528.txt")));
}

#[test]
fn tv_529() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-529.txt")));
}

#[test]
fn tv_530() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-530.txt")));
}

#[test]
fn tv_531() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-531.txt")));
}

#[test]
fn tv_532() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-532.txt")));
}

#[test]
fn tv_533() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-533.txt")));
}

#[test]
fn tv_534() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-534.txt")));
}

#[test]
fn tv_535() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-535.txt")));
}

#[test]
fn tv_536() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-536.txt")));
}

#[test]
fn tv_537() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-537.txt")));
}

#[test]
fn tv_538() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-538.txt")));
}

#[test]
fn tv_539() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-539.txt")));
}

#[test]
fn tv_540() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-540.txt")));
}

#[test]
fn tv_541() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-541.txt")));
}

#[test]
fn tv_542() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-542.txt")));
}

#[test]
fn tv_543() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-543.txt")));
}

#[test]
fn tv_544() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-544.txt")));
}

#[test]
fn tv_545() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-545.txt")));
}

#[test]
fn tv_546() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-546.txt")));
}

#[test]
fn tv_547() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-547.txt")));
}

#[test]
fn tv_548() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-548.txt")));
}

#[test]
fn tv_549() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-549.txt")));
}

#[test]
fn tv_550() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-550.txt")));
}

#[test]
fn tv_551() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-551.txt")));
}

#[test]
fn tv_552() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-552.txt")));
}

#[test]
fn tv_553() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-553.txt")));
}

#[test]
fn tv_554() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-554.txt")));
}

#[test]
fn tv_555() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-555.txt")));
}

#[test]
fn tv_556() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-556.txt")));
}

#[test]
fn tv_557() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-557.txt")));
}

#[test]
fn tv_558() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-558.txt")));
}

#[test]
fn tv_559() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-559.txt")));
}

#[test]
fn tv_560() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-560.txt")));
}

#[test]
fn tv_561() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-561.txt")));
}

#[test]
fn tv_562() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-562.txt")));
}

#[test]
fn tv_563() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-563.txt")));
}

#[test]
fn tv_564() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-564.txt")));
}

#[test]
fn tv_565() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-565.txt")));
}

#[test]
fn tv_566() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-566.txt")));
}

#[test]
fn tv_567() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-567.txt")));
}

#[test]
fn tv_568() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-568.txt")));
}

#[test]
fn tv_569() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-569.txt")));
}

#[test]
fn tv_570() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-570.txt")));
}

#[test]
fn tv_571() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-571.txt")));
}

#[test]
fn tv_572() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-572.txt")));
}

#[test]
fn tv_573() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-573.txt")));
}

#[test]
fn tv_574() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-574.txt")));
}

#[test]
fn tv_575() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-575.txt")));
}

#[test]
fn tv_576() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-576.txt")));
}

#[test]
fn tv_577() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-577.txt")));
}

#[test]
fn tv_578() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-578.txt")));
}

#[test]
fn tv_579() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-579.txt")));
}

#[test]
fn tv_580() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-580.txt")));
}

#[test]
fn tv_581() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-581.txt")));
}

#[test]
fn tv_582() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-582.txt")));
}

#[test]
fn tv_583() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-583.txt")));
}

#[test]
fn tv_584() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-584.txt")));
}

#[test]
fn tv_585() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-585.txt")));
}

#[test]
fn tv_586() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-586.txt")));
}

#[test]
fn tv_587() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-587.txt")));
}

#[test]
fn tv_588() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-588.txt")));
}

#[test]
fn tv_589() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-589.txt")));
}

#[test]
fn tv_590() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-590.txt")));
}

#[test]
fn tv_591() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-591.txt")));
}

#[test]
fn tv_592() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-592.txt")));
}

#[test]
fn tv_593() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-593.txt")));
}

#[test]
fn tv_594() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-594.txt")));
}

#[test]
fn tv_595() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-595.txt")));
}

#[test]
fn tv_596() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-596.txt")));
}

#[test]
fn tv_597() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-597.txt")));
}

#[test]
fn tv_598() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-598.txt")));
}

#[test]
fn tv_599() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-599.txt")));
}

#[test]
fn tv_600() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-600.txt")));
}

#[test]
fn tv_601() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-601.txt")));
}

#[test]
fn tv_602() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-602.txt")));
}

#[test]
fn tv_603() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-603.txt")));
}

#[test]
fn tv_604() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-604.txt")));
}

#[test]
fn tv_605() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-605.txt")));
}

#[test]
fn tv_606() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-606.txt")));
}

#[test]
fn tv_607() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-607.txt")));
}

#[test]
fn tv_608() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-608.txt")));
}

#[test]
fn tv_609() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-609.txt")));
}

#[test]
fn tv_610() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-610.txt")));
}

#[test]
fn tv_611() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-611.txt")));
}

#[test]
fn tv_612() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-612.txt")));
}

#[test]
fn tv_613() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-613.txt")));
}

#[test]
fn tv_614() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-614.txt")));
}

#[test]
fn tv_615() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-615.txt")));
}

#[test]
fn tv_616() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-616.txt")));
}

#[test]
fn tv_617() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-617.txt")));
}

#[test]
fn tv_618() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-618.txt")));
}

#[test]
fn tv_619() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-619.txt")));
}

#[test]
fn tv_620() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-620.txt")));
}

#[test]
fn tv_621() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-621.txt")));
}

#[test]
fn tv_622() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-622.txt")));
}

#[test]
fn tv_623() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-623.txt")));
}

#[test]
fn tv_624() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-624.txt")));
}

#[test]
fn tv_625() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-625.txt")));
}

#[test]
fn tv_626() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-626.txt")));
}

#[test]
fn tv_627() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-627.txt")));
}

#[test]
fn tv_628() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-628.txt")));
}

#[test]
fn tv_629() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-629.txt")));
}

#[test]
fn tv_630() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-630.txt")));
}

#[test]
fn tv_631() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-631.txt")));
}

#[test]
fn tv_632() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-632.txt")));
}

#[test]
fn tv_633() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-633.txt")));
}

#[test]
fn tv_634() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-634.txt")));
}

#[test]
fn tv_635() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-635.txt")));
}

#[test]
fn tv_636() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-636.txt")));
}

#[test]
fn tv_637() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-637.txt")));
}

#[test]
fn tv_638() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-638.txt")));
}

#[test]
fn tv_639() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-639.txt")));
}

#[test]
fn tv_640() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-640.txt")));
}

#[test]
fn tv_641() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-641.txt")));
}

#[test]
fn tv_642() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-642.txt")));
}

#[test]
fn tv_643() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-643.txt")));
}

#[test]
fn tv_644() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-644.txt")));
}

#[test]
fn tv_645() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-645.txt")));
}

#[test]
fn tv_646() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-646.txt")));
}

#[test]
fn tv_647() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-647.txt")));
}

#[test]
fn tv_648() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-648.txt")));
}

#[test]
fn tv_649() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-649.txt")));
}

#[test]
fn tv_650() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-650.txt")));
}

#[test]
fn tv_651() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-651.txt")));
}

#[test]
fn tv_652() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-652.txt")));
}

#[test]
fn tv_653() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-653.txt")));
}

#[test]
fn tv_654() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-654.txt")));
}

#[test]
fn tv_655() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-655.txt")));
}

#[test]
fn tv_656() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-656.txt")));
}

#[test]
fn tv_657() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-657.txt")));
}

#[test]
fn tv_658() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-658.txt")));
}

#[test]
fn tv_659() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-659.txt")));
}

#[test]
fn tv_660() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-660.txt")));
}

#[test]
fn tv_661() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-661.txt")));
}

#[test]
fn tv_662() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-662.txt")));
}

#[test]
fn tv_663() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-663.txt")));
}

#[test]
fn tv_664() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-664.txt")));
}

#[test]
fn tv_665() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-665.txt")));
}

#[test]
fn tv_666() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-666.txt")));
}

#[test]
fn tv_667() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-667.txt")));
}

#[test]
fn tv_668() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-668.txt")));
}

#[test]
fn tv_669() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-669.txt")));
}

#[test]
fn tv_670() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-670.txt")));
}

#[test]
fn tv_671() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-671.txt")));
}

#[test]
fn tv_672() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-672.txt")));
}

#[test]
fn tv_673() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-673.txt")));
}

#[test]
fn tv_674() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-674.txt")));
}

#[test]
fn tv_675() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-675.txt")));
}

#[test]
fn tv_676() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-676.txt")));
}

#[test]
fn tv_677() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-677.txt")));
}

#[test]
fn tv_678() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-678.txt")));
}

#[test]
fn tv_679() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-679.txt")));
}

#[test]
fn tv_680() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-680.txt")));
}

#[test]
fn tv_681() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-681.txt")));
}

#[test]
fn tv_682() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-682.txt")));
}

#[test]
fn tv_683() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-683.txt")));
}

#[test]
fn tv_684() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-684.txt")));
}

#[test]
fn tv_685() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-685.txt")));
}

#[test]
fn tv_686() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-686.txt")));
}

#[test]
fn tv_687() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-687.txt")));
}

#[test]
fn tv_688() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-688.txt")));
}

#[test]
fn tv_689() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-689.txt")));
}

#[test]
fn tv_690() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-690.txt")));
}

#[test]
fn tv_691() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-691.txt")));
}

#[test]
fn tv_692() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-692.txt")));
}

#[test]
fn tv_693() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-693.txt")));
}

#[test]
fn tv_694() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-694.txt")));
}

#[test]
fn tv_695() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-695.txt")));
}

#[test]
fn tv_696() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-696.txt")));
}

#[test]
fn tv_697() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-697.txt")));
}

#[test]
fn tv_698() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-698.txt")));
}

#[test]
fn tv_699() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-699.txt")));
}

#[test]
fn tv_700() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-700.txt")));
}

#[test]
fn tv_701() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-701.txt")));
}

#[test]
fn tv_702() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-702.txt")));
}

#[test]
fn tv_703() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-703.txt")));
}

#[test]
fn tv_704() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-704.txt")));
}

#[test]
fn tv_705() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-705.txt")));
}

#[test]
fn tv_706() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-706.txt")));
}

#[test]
fn tv_707() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-707.txt")));
}

#[test]
fn tv_708() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-708.txt")));
}

#[test]
fn tv_709() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-709.txt")));
}

#[test]
fn tv_710() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-710.txt")));
}

#[test]
fn tv_711() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-711.txt")));
}

#[test]
fn tv_712() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-712.txt")));
}

#[test]
fn tv_713() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-713.txt")));
}

#[test]
fn tv_714() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-714.txt")));
}

#[test]
fn tv_715() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-715.txt")));
}

#[test]
fn tv_716() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-716.txt")));
}

#[test]
fn tv_717() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-717.txt")));
}

#[test]
fn tv_718() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-718.txt")));
}

#[test]
fn tv_719() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-719.txt")));
}

#[test]
fn tv_720() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-720.txt")));
}

#[test]
fn tv_721() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-721.txt")));
}

#[test]
fn tv_722() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-722.txt")));
}

#[test]
fn tv_723() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-723.txt")));
}

#[test]
fn tv_724() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-724.txt")));
}

#[test]
fn tv_725() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-725.txt")));
}

#[test]
fn tv_726() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-726.txt")));
}

#[test]
fn tv_727() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-727.txt")));
}

#[test]
fn tv_728() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-728.txt")));
}

#[test]
fn tv_729() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-729.txt")));
}

#[test]
fn tv_730() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-730.txt")));
}

#[test]
fn tv_731() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-731.txt")));
}

#[test]
fn tv_732() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-732.txt")));
}

#[test]
fn tv_733() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-733.txt")));
}

#[test]
fn tv_734() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-734.txt")));
}

#[test]
fn tv_735() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-735.txt")));
}

#[test]
fn tv_736() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-736.txt")));
}

#[test]
fn tv_737() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-737.txt")));
}

#[test]
fn tv_738() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-738.txt")));
}

#[test]
fn tv_739() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-739.txt")));
}

#[test]
fn tv_740() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-740.txt")));
}

#[test]
fn tv_741() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-741.txt")));
}

#[test]
fn tv_742() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-742.txt")));
}

#[test]
fn tv_743() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-743.txt")));
}

#[test]
fn tv_744() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-744.txt")));
}

#[test]
fn tv_745() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-745.txt")));
}

#[test]
fn tv_746() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-746.txt")));
}

#[test]
fn tv_747() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-747.txt")));
}

#[test]
fn tv_748() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-748.txt")));
}

#[test]
fn tv_749() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-749.txt")));
}

#[test]
fn tv_750() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-750.txt")));
}

#[test]
fn tv_751() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-751.txt")));
}

#[test]
fn tv_752() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-752.txt")));
}

#[test]
fn tv_753() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-753.txt")));
}

#[test]
fn tv_754() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-754.txt")));
}

#[test]
fn tv_755() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-755.txt")));
}

#[test]
fn tv_756() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-756.txt")));
}

#[test]
fn tv_757() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-757.txt")));
}

#[test]
fn tv_758() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-758.txt")));
}

#[test]
fn tv_759() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-759.txt")));
}

#[test]
fn tv_760() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-760.txt")));
}

#[test]
fn tv_761() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-761.txt")));
}

#[test]
fn tv_762() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-762.txt")));
}

#[test]
fn tv_763() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-763.txt")));
}

#[test]
fn tv_764() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-764.txt")));
}

#[test]
fn tv_765() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-765.txt")));
}

#[test]
fn tv_766() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-766.txt")));
}

#[test]
fn tv_767() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-767.txt")));
}

#[test]
fn tv_768() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-768.txt")));
}

#[test]
fn tv_769() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-769.txt")));
}

#[test]
fn tv_770() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-770.txt")));
}

#[test]
fn tv_771() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-771.txt")));
}

#[test]
fn tv_772() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-772.txt")));
}

#[test]
fn tv_773() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-773.txt")));
}

#[test]
fn tv_774() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-774.txt")));
}

#[test]
fn tv_775() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-775.txt")));
}

#[test]
fn tv_776() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-776.txt")));
}

#[test]
fn tv_777() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-777.txt")));
}

#[test]
fn tv_778() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-778.txt")));
}

#[test]
fn tv_779() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-779.txt")));
}

#[test]
fn tv_780() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-780.txt")));
}

#[test]
fn tv_781() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-781.txt")));
}

#[test]
fn tv_782() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-782.txt")));
}

#[test]
fn tv_783() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-783.txt")));
}

#[test]
fn tv_784() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-784.txt")));
}

#[test]
fn tv_785() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-785.txt")));
}

#[test]
fn tv_786() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-786.txt")));
}

#[test]
fn tv_787() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-787.txt")));
}

#[test]
fn tv_788() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-788.txt")));
}

#[test]
fn tv_789() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-789.txt")));
}

#[test]
fn tv_790() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-790.txt")));
}

#[test]
fn tv_791() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-791.txt")));
}

#[test]
fn tv_792() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-792.txt")));
}

#[test]
fn tv_793() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-793.txt")));
}

#[test]
fn tv_794() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-794.txt")));
}

#[test]
fn tv_795() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-795.txt")));
}

#[test]
fn tv_796() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-796.txt")));
}

#[test]
fn tv_797() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-797.txt")));
}

#[test]
fn tv_798() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-798.txt")));
}

#[test]
fn tv_799() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-799.txt")));
}

#[test]
fn tv_800() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-800.txt")));
}

#[test]
fn tv_801() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-801.txt")));
}

#[test]
fn tv_802() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-802.txt")));
}

#[test]
fn tv_803() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-803.txt")));
}

#[test]
fn tv_804() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-804.txt")));
}

#[test]
fn tv_805() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-805.txt")));
}

#[test]
fn tv_806() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-806.txt")));
}

#[test]
fn tv_807() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-807.txt")));
}

#[test]
fn tv_808() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-808.txt")));
}

#[test]
fn tv_809() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-809.txt")));
}

#[test]
fn tv_810() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-810.txt")));
}

#[test]
fn tv_811() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-811.txt")));
}

#[test]
fn tv_812() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-812.txt")));
}

#[test]
fn tv_813() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-813.txt")));
}

#[test]
fn tv_814() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-814.txt")));
}

#[test]
fn tv_815() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-815.txt")));
}

#[test]
fn tv_816() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-816.txt")));
}

#[test]
fn tv_817() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-817.txt")));
}

#[test]
fn tv_818() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-818.txt")));
}

#[test]
fn tv_819() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-819.txt")));
}

#[test]
fn tv_820() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-820.txt")));
}

#[test]
fn tv_821() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-821.txt")));
}

#[test]
fn tv_822() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-822.txt")));
}

#[test]
fn tv_823() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-823.txt")));
}

#[test]
fn tv_824() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-824.txt")));
}

#[test]
fn tv_825() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-825.txt")));
}

#[test]
fn tv_826() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-826.txt")));
}

#[test]
fn tv_827() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-827.txt")));
}

#[test]
fn tv_828() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-828.txt")));
}

#[test]
fn tv_829() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-829.txt")));
}

#[test]
fn tv_830() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-830.txt")));
}

#[test]
fn tv_831() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-831.txt")));
}

#[test]
fn tv_832() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-832.txt")));
}

#[test]
fn tv_833() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-833.txt")));
}

#[test]
fn tv_834() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-834.txt")));
}

#[test]
fn tv_835() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-835.txt")));
}

#[test]
fn tv_836() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-836.txt")));
}

#[test]
fn tv_837() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-837.txt")));
}

#[test]
fn tv_838() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-838.txt")));
}

#[test]
fn tv_839() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-839.txt")));
}

#[test]
fn tv_840() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-840.txt")));
}

#[test]
fn tv_841() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-841.txt")));
}

#[test]
fn tv_842() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-842.txt")));
}

#[test]
fn tv_843() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-843.txt")));
}

#[test]
fn tv_844() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-844.txt")));
}

#[test]
fn tv_845() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-845.txt")));
}

#[test]
fn tv_846() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-846.txt")));
}

#[test]
fn tv_847() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-847.txt")));
}

#[test]
fn tv_848() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-848.txt")));
}

#[test]
fn tv_849() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-849.txt")));
}

#[test]
fn tv_850() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-850.txt")));
}

#[test]
fn tv_851() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-851.txt")));
}

#[test]
fn tv_852() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-852.txt")));
}

#[test]
fn tv_853() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-853.txt")));
}

#[test]
fn tv_854() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-854.txt")));
}

#[test]
fn tv_855() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-855.txt")));
}

#[test]
fn tv_856() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-856.txt")));
}

#[test]
fn tv_857() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-857.txt")));
}

#[test]
fn tv_858() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-858.txt")));
}

#[test]
fn tv_859() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-859.txt")));
}

#[test]
fn tv_860() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-860.txt")));
}

#[test]
fn tv_861() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-861.txt")));
}

#[test]
fn tv_862() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-862.txt")));
}

#[test]
fn tv_863() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-863.txt")));
}

#[test]
fn tv_864() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-864.txt")));
}

#[test]
fn tv_865() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-865.txt")));
}

#[test]
fn tv_866() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-866.txt")));
}

#[test]
fn tv_867() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-867.txt")));
}

#[test]
fn tv_868() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-868.txt")));
}

#[test]
fn tv_869() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-869.txt")));
}

#[test]
fn tv_870() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-870.txt")));
}

#[test]
fn tv_871() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-871.txt")));
}

#[test]
fn tv_872() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-872.txt")));
}

#[test]
fn tv_873() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-873.txt")));
}

#[test]
fn tv_874() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-874.txt")));
}

#[test]
fn tv_875() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-875.txt")));
}

#[test]
fn tv_876() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-876.txt")));
}

#[test]
fn tv_877() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-877.txt")));
}

#[test]
fn tv_878() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-878.txt")));
}

#[test]
fn tv_879() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-879.txt")));
}

#[test]
fn tv_880() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-880.txt")));
}

#[test]
fn tv_881() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-881.txt")));
}

#[test]
fn tv_882() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-882.txt")));
}

#[test]
fn tv_883() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-883.txt")));
}

#[test]
fn tv_884() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-884.txt")));
}

#[test]
fn tv_885() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-885.txt")));
}

#[test]
fn tv_886() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-886.txt")));
}

#[test]
fn tv_887() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-887.txt")));
}

#[test]
fn tv_888() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-888.txt")));
}

#[test]
fn tv_889() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-889.txt")));
}

#[test]
fn tv_890() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-890.txt")));
}

#[test]
fn tv_891() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-891.txt")));
}

#[test]
fn tv_892() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-892.txt")));
}

#[test]
fn tv_893() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-893.txt")));
}

#[test]
fn tv_894() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-894.txt")));
}

#[test]
fn tv_895() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-895.txt")));
}

#[test]
fn tv_896() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-896.txt")));
}

#[test]
fn tv_897() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-897.txt")));
}

#[test]
fn tv_898() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-898.txt")));
}

#[test]
fn tv_899() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-899.txt")));
}

#[test]
fn tv_900() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-900.txt")));
}

#[test]
fn tv_901() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-901.txt")));
}

#[test]
fn tv_902() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-902.txt")));
}

#[test]
fn tv_903() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-903.txt")));
}

#[test]
fn tv_904() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-904.txt")));
}

#[test]
fn tv_905() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-905.txt")));
}

#[test]
fn tv_906() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-906.txt")));
}

#[test]
fn tv_907() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-907.txt")));
}

#[test]
fn tv_908() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-908.txt")));
}

#[test]
fn tv_909() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-909.txt")));
}

#[test]
fn tv_910() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-910.txt")));
}

#[test]
fn tv_911() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-911.txt")));
}

#[test]
fn tv_912() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-912.txt")));
}

#[test]
fn tv_913() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-913.txt")));
}

#[test]
fn tv_914() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-914.txt")));
}

#[test]
fn tv_915() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-915.txt")));
}

#[test]
fn tv_916() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-916.txt")));
}

#[test]
fn tv_917() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-917.txt")));
}

#[test]
fn tv_918() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-918.txt")));
}

#[test]
fn tv_919() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-919.txt")));
}

#[test]
fn tv_920() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-920.txt")));
}

#[test]
fn tv_921() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-921.txt")));
}

#[test]
fn tv_922() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-922.txt")));
}

#[test]
fn tv_923() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-923.txt")));
}

#[test]
fn tv_924() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-924.txt")));
}

#[test]
fn tv_925() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-925.txt")));
}

#[test]
fn tv_926() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-926.txt")));
}

#[test]
fn tv_927() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-927.txt")));
}

#[test]
fn tv_928() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-928.txt")));
}

#[test]
fn tv_929() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-929.txt")));
}

#[test]
fn tv_930() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-930.txt")));
}

#[test]
fn tv_931() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-931.txt")));
}

#[test]
fn tv_932() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-932.txt")));
}

#[test]
fn tv_933() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-933.txt")));
}

#[test]
fn tv_934() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-934.txt")));
}

#[test]
fn tv_935() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-935.txt")));
}

#[test]
fn tv_936() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-936.txt")));
}

#[test]
fn tv_937() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-937.txt")));
}

#[test]
fn tv_938() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-938.txt")));
}

#[test]
fn tv_939() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-939.txt")));
}

#[test]
fn tv_940() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-940.txt")));
}

#[test]
fn tv_941() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-941.txt")));
}

#[test]
fn tv_942() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-942.txt")));
}

#[test]
fn tv_943() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-943.txt")));
}

#[test]
fn tv_944() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-944.txt")));
}

#[test]
fn tv_945() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-945.txt")));
}

#[test]
fn tv_946() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-946.txt")));
}

#[test]
fn tv_947() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-947.txt")));
}

#[test]
fn tv_948() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-948.txt")));
}

#[test]
fn tv_949() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-949.txt")));
}

#[test]
fn tv_950() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-950.txt")));
}

#[test]
fn tv_951() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-951.txt")));
}

#[test]
fn tv_952() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-952.txt")));
}

#[test]
fn tv_953() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-953.txt")));
}

#[test]
fn tv_954() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-954.txt")));
}

#[test]
fn tv_955() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-955.txt")));
}

#[test]
fn tv_956() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-956.txt")));
}

#[test]
fn tv_957() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-957.txt")));
}

#[test]
fn tv_958() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-958.txt")));
}

#[test]
fn tv_959() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-959.txt")));
}

#[test]
fn tv_960() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-960.txt")));
}

#[test]
fn tv_961() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-961.txt")));
}

#[test]
fn tv_962() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-962.txt")));
}

#[test]
fn tv_963() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-963.txt")));
}

#[test]
fn tv_964() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-964.txt")));
}

#[test]
fn tv_965() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-965.txt")));
}

#[test]
fn tv_966() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-966.txt")));
}

#[test]
fn tv_967() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-967.txt")));
}

#[test]
fn tv_968() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-968.txt")));
}

#[test]
fn tv_969() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-969.txt")));
}

#[test]
fn tv_970() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-970.txt")));
}

#[test]
fn tv_971() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-971.txt")));
}

#[test]
fn tv_972() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-972.txt")));
}

#[test]
fn tv_973() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-973.txt")));
}

#[test]
fn tv_974() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-974.txt")));
}

#[test]
fn tv_975() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-975.txt")));
}

#[test]
fn tv_976() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-976.txt")));
}

#[test]
fn tv_977() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-977.txt")));
}

#[test]
fn tv_978() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-978.txt")));
}

#[test]
fn tv_979() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-979.txt")));
}

#[test]
fn tv_980() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-980.txt")));
}

#[test]
fn tv_981() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-981.txt")));
}

#[test]
fn tv_982() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-982.txt")));
}

#[test]
fn tv_983() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-983.txt")));
}

#[test]
fn tv_984() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-984.txt")));
}

#[test]
fn tv_985() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-985.txt")));
}

#[test]
fn tv_986() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-986.txt")));
}

#[test]
fn tv_987() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-987.txt")));
}

#[test]
fn tv_988() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-988.txt")));
}

#[test]
fn tv_989() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-989.txt")));
}

#[test]
fn tv_990() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-990.txt")));
}

#[test]
fn tv_991() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-991.txt")));
}

#[test]
fn tv_992() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-992.txt")));
}

#[test]
fn tv_993() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-993.txt")));
}

#[test]
fn tv_994() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-994.txt")));
}

#[test]
fn tv_995() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-995.txt")));
}

#[test]
fn tv_996() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-996.txt")));
}

#[test]
fn tv_997() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-997.txt")));
}

#[test]
fn tv_998() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-998.txt")));
}

#[test]
fn tv_999() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-999.txt")));
}

#[test]
fn tv_1000() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1000.txt")));
}

#[test]
fn tv_1001() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1001.txt")));
}

#[test]
fn tv_1002() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1002.txt")));
}

#[test]
fn tv_1003() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1003.txt")));
}

#[test]
fn tv_1004() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1004.txt")));
}

#[test]
fn tv_1005() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1005.txt")));
}

#[test]
fn tv_1006() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1006.txt")));
}

#[test]
fn tv_1007() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1007.txt")));
}

#[test]
fn tv_1008() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1008.txt")));
}

#[test]
fn tv_1009() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1009.txt")));
}

#[test]
fn tv_1010() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1010.txt")));
}

#[test]
fn tv_1011() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1011.txt")));
}

#[test]
fn tv_1012() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1012.txt")));
}

#[test]
fn tv_1013() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1013.txt")));
}

#[test]
fn tv_1014() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1014.txt")));
}

#[test]
fn tv_1015() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1015.txt")));
}

#[test]
fn tv_1016() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1016.txt")));
}

#[test]
fn tv_1017() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1017.txt")));
}

#[test]
fn tv_1018() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1018.txt")));
}

#[test]
fn tv_1019() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1019.txt")));
}

#[test]
fn tv_1020() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1020.txt")));
}

#[test]
fn tv_1021() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1021.txt")));
}

#[test]
fn tv_1022() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1022.txt")));
}

#[test]
fn tv_1023() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1023.txt")));
}

#[test]
fn tv_1024() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1024.txt")));
}

#[test]
fn tv_1025() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1025.txt")));
}

#[test]
fn tv_1026() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1026.txt")));
}

#[test]
fn tv_1027() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1027.txt")));
}

#[test]
fn tv_1028() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1028.txt")));
}

#[test]
fn tv_1029() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1029.txt")));
}

#[test]
fn tv_1030() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1030.txt")));
}

#[test]
fn tv_1031() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1031.txt")));
}

#[test]
fn tv_1032() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1032.txt")));
}

#[test]
fn tv_1033() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1033.txt")));
}

#[test]
fn tv_1034() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1034.txt")));
}

#[test]
fn tv_1035() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1035.txt")));
}

#[test]
fn tv_1036() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1036.txt")));
}

#[test]
fn tv_1037() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1037.txt")));
}

#[test]
fn tv_1038() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1038.txt")));
}

#[test]
fn tv_1039() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1039.txt")));
}

#[test]
fn tv_1040() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1040.txt")));
}

#[test]
fn tv_1041() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1041.txt")));
}

#[test]
fn tv_1042() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1042.txt")));
}

#[test]
fn tv_1043() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1043.txt")));
}

#[test]
fn tv_1044() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1044.txt")));
}

#[test]
fn tv_1045() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1045.txt")));
}

#[test]
fn tv_1046() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1046.txt")));
}

#[test]
fn tv_1047() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1047.txt")));
}

#[test]
fn tv_1048() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1048.txt")));
}

#[test]
fn tv_1049() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1049.txt")));
}

#[test]
fn tv_1050() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1050.txt")));
}

#[test]
fn tv_1051() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1051.txt")));
}

#[test]
fn tv_1052() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1052.txt")));
}

#[test]
fn tv_1053() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1053.txt")));
}

#[test]
fn tv_1054() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1054.txt")));
}

#[test]
fn tv_1055() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1055.txt")));
}

#[test]
fn tv_1056() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1056.txt")));
}

#[test]
fn tv_1057() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1057.txt")));
}

#[test]
fn tv_1058() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1058.txt")));
}

#[test]
fn tv_1059() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1059.txt")));
}

#[test]
fn tv_1060() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1060.txt")));
}

#[test]
fn tv_1061() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1061.txt")));
}

#[test]
fn tv_1062() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1062.txt")));
}

#[test]
fn tv_1063() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1063.txt")));
}

#[test]
fn tv_1064() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1064.txt")));
}

#[test]
fn tv_1065() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1065.txt")));
}

#[test]
fn tv_1066() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1066.txt")));
}

#[test]
fn tv_1067() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1067.txt")));
}

#[test]
fn tv_1068() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1068.txt")));
}

#[test]
fn tv_1069() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1069.txt")));
}

#[test]
fn tv_1070() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1070.txt")));
}

#[test]
fn tv_1071() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1071.txt")));
}

#[test]
fn tv_1072() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1072.txt")));
}

#[test]
fn tv_1073() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1073.txt")));
}

#[test]
fn tv_1074() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1074.txt")));
}

#[test]
fn tv_1075() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1075.txt")));
}

#[test]
fn tv_1076() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1076.txt")));
}

#[test]
fn tv_1077() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1077.txt")));
}

#[test]
fn tv_1078() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1078.txt")));
}

#[test]
fn tv_1079() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1079.txt")));
}

#[test]
fn tv_1080() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1080.txt")));
}

#[test]
fn tv_1081() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1081.txt")));
}

#[test]
fn tv_1082() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1082.txt")));
}

#[test]
fn tv_1083() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1083.txt")));
}

#[test]
fn tv_1084() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1084.txt")));
}

#[test]
fn tv_1085() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1085.txt")));
}

#[test]
fn tv_1086() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1086.txt")));
}

#[test]
fn tv_1087() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1087.txt")));
}

#[test]
fn tv_1088() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1088.txt")));
}

#[test]
fn tv_1089() {
    run_tv(parse_tv(include_str!("ascon128v12-KATs/AEAD_KAT-1089.txt")));
}
