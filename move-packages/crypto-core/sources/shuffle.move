/// The on-chain states/util functions of a shuffle process where:
/// a list of users take turns to verifiably shuffle a list of ElGamal ciphertexts.
module crypto_core::shuffle {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector::range;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_framework::randomness;
    use aptos_framework::timestamp;
    use crypto_core::group;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::pedersen_commitment;
    use crypto_core::bg12;
    use crypto_core::elgamal;
    #[test_only]
    use std::bcs;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_std::debug::print;

    const STATE__ACCEPTING_CONTRIBUTION: u64 = 1;
    const STATE__SUCCEEDED: u64 = 2;
    const STATE__FAILED: u64 = 3;

    struct VerifiableContribution has copy, drop, store {
        new_ciphertexts: vector<elgamal::Ciphertext>,
        proof: Option<bg12::Proof>,
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            new_ciphertexts: vector[],
            proof: option::none(),
        }
    }

    /// Gas cost: 205 (proof == null).
    public fun decode_contribution(stream: &mut BCSStream): VerifiableContribution {
        let new_ciphertexts = bcs_stream::deserialize_vector(stream, |s|elgamal::decode_ciphertext(s));
        let proof = bcs_stream::deserialize_option(stream, |s|bg12::decode_proof(s));
        VerifiableContribution { new_ciphertexts, proof }
    }

    // const XAMPLE: vector<u8> = x"34201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d80578e00c4fe5c8db0764b0e5f921fcfccf62264dfa85151b15bf6a9d96e43120240b3fe85a16d548ba4e6007c9334224932e41d20de9d99b421356977f76793b201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2064596e40a51cab999886326cae6e03eba8a71921e526ffc9957e55251d1f410c204a2dd43e53187424ad882a3167d809f2dd1ded899d085c9ec6103025b914b50c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207a234f45fe50de29a0ce40e01aed93b9171d76aea34b5464ad99b11529df260920726215288aa50c1d739cdc0445f72d557bc07cfef7beb0ba337f7afa5f5dbe11201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20408706723241063a22aae5cac23972193537cac7329b39cf3742cbc2a6f7d86c201a5dda0944d449f4773efc0b703d79090f0f7c650bb9877d0bf0e04e64c01656201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d4c2cf839428678be1be51b49d183e31f117610f841885032c123c58d6a98b7820ee43592f98d94f0ca01381417b125b16216efc2551c9cbe39005b2792eada41f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209222a70c6ddd518e59cf28b8451700f755abb9de02cdc10180a03e7f5a4f29692026ccd5fe2e74017d22e5f5d6413eefffb1be2fdab83c7aa1bffcd0000fa0d00a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20e0b35d9c7ae455232aa41bd184ed4bfb55070765b702004292da1c1cdbae1549209ee590ab0c6191c5ac5e4e10416a0f434095d8e575551ee805c966d193698e1c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d201471e7cf1f9f7124501c5221b5e76ac11846ce1b87ac848ea589b0cc58ff3641201001088aaf6e5397cbc0a044b6859d4a3da98201d00d8675b96b4edd9febb009201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20a0af866f04fd79960416c7aba9ef33d1bbd0953d205c473f498377d8d53ec77c20406323a711b904a77d7973393b114d479eac9685b0f472ffd2f87161025cb700201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202084c347e99d2be9d1665fa66268a01800397858242c7e7c11a9781fa5f14952209474ea0952ea16b0c92e5c20a0d5cd74f001218e9b11307cee9c717c4c73b629201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2008204fb6d21aca04e00d5e1711416e380ea1e16e834a986c2cbd62731fe65c4c20e02a3ed6ae7ac7e38cbb411863c2bf7e6f61e71bfc51ff40843a5a7a692f0e5f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20221ddec46431af52601d816ba28103235ffa4591b98b2ddb1e9362b5976831542060605cf7e442d75e1df8a5b74981dd225dd9ff8b3b7e64b630da7cf1d915c24a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d206e021beeb13173cd2b9e21756543578fec7b41a8abce001f0651640447175340208824cb7ab5ad18aeeaebd7066efc374213b962021040507fa05f81a3a3c71624201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d203c991be79195e213c3bfc4dd375aa65f38af2b4355e3fb2f1756047d6e8f9c122066858b68831a46d0046b389f59536a33bd39698f21e6e8030a0ee75fb349c34c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207e7b040e7267d9125ba22541deaffb6aed12001145ee0e89eabde793d776833c20de8b8780a4f7aaac080813be5f71a292167eecb4243e216a51db1aee19d5e323201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d208e7c9608252eca2767d0e82a72c759d7a2acaf4f2cadc4be16b5b07a6661b60f20727ca0e031def7a47563ad466114c8224a54713416fd2b6f78be66c62ca64b64201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20f2997cafe6215ebf1cb2844494ec7fe218d1d14a200728c3066ecaba1098326720068b7a7dc78dc34329490e2ade25e666a8e18b56ed676e796fed06bb252a8b39201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209c08980fa75099e1f736a05ca8067e371200a82dc2389c913a28bee4db95fd5a209c344cb0abb784303304b584721fac934237a792ef01c28f05b9f1ee3cfa4308201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20aaa79e298d21acf11d2b3eb3b1b218b5af4f82e390829a86df93feeb10cf917220d0ad381f21c38ef6b6de73567d2c5b70b543ce17a41ef77d6cf3fc0642d99f0e201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d206c96230c383c6b1e7c41666612c09a43898e34607b859a3e6ec1e1f18e58c74f2040935aa100e8561a51385d6c8acd19f611c81b9406a09d5f5433f3215d295527201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d204635f18340703c4a8e5902c057e8169da97ce0ded296a8914ca735294a0a8e4f200e82ae048a1af5dea7d4ac91afe2d38e9d527fdd59c4dfc504ab09448668ad3f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20a6b2feec2aa76822024c4d785dadc46aacd779d46373d5e9090d2623b026040920204250aeb63936131c4067d499a3dcd0cfcfd4342e135d96fc2e8a96b5e7e60d201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20c0dc4ac50738c41f1c2929514a27ecf1f6d5da64e25944a79f02dcf3a7811d102000d8e9d5e4ff2e1bbe03e3c41ec0b329828732d1fc58121a005f150906176041201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2064591e3c00d4329199c18bbb5b43b47508156fffd4db1688390f5a093c9f02362002ef25e7b10222a335ac36bba92785615de070c3626b70685a3a18502b2f770a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d224d884f45a426b5fa52b36618a8aa9b84f9848d4bcea41d92c6e134579f57420cc93ebcf1d4cb545a01bb6faecc39e2230868421f49955f5ab0e16c566373f10201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ae25b267107b903d5390460565c3567a2d5efe4f863d6a00144670dbb542e2642094d127b4dde113544ad88b7d49ada2b7f879af6a4d515dab41d5e3651eb55228201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202ee91f1ced4d521bdfc60e448bec1989b952324effe1b008287715750620432c20b626a8e7d19ec92bc19ee021b626a6702a8cbe4f8110678d965d468460b06762201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2032c17bd42ff10cdd45a619ac002fcaa698500115479ab49c47908d6c33056c57206a5cb4d2d9a89bd56c238ef3418f5785784ac01e7e60a4f636353b8b3aa8071f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2040af58aabb26e0b00088ea61fc22486b66cca835ebdf36a126641549cd6a7a662044672b80efa73471150626646fae0e1fc8f2d0f56d5f540aedcfab2cebee2d67201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202288e60c6fafb365a5d3837deeb9fd615936a3baa613b0037c93e6f553f60c21208e82d6ff01e4fb19a5171e51f2f70f76b8478f161be58cf3a49551e1ff833e44201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ae7154f6b7001de249e771f53cf21c7d5545bd401ea3f1bbb21bee835810380b20a0c6412f8c543f5140bfb2402ed102f59a16b77bdb261a31e96b1796bfab2478201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205a368373de62007eb64258aa2dad3db0f83f4a04a7a0e497083b9118dbbf884c20be95d3580c127f049811d9e21c6987aefec510bcbe3696491d7babc3974b6c03201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209258035f90853a3d15d5323c6865345c29aa5b54cc7b18e1cdc08e7aa6255d20204874b6dd11c1fcb27dae45bcb5d7ceae4ecac976aab6283b2746c80581fb6a54201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d201c600d557b6cb48baf5985ab49824954ac86fdae77ee4dc9a1629717f333032b20e4a967c4647aa5f4030eda6b1dbfc0f7c46edaf7f960c1fe8dc0a4b454586616201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205230d663e5a0b468600d7d07afc615bb93e295d59fbc166a67e1d1c480eb4d7920d8a469f338e837697002fad72244abe3b8c9f4992d408d80aba74db98eb75a70201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2072ecd17bf84745b4ee2339ccd89b714286c80bf1d4d68cb0585813f8b8765a62205478697f9c8b4c96a3c72da7527a1128692bec3dac2982a154ea4f8039cafa22201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2044e46466e1b1144c44f441db3a2560c60294318c22db262fa55c1152fbe31961203eb7e8fe5329ab2df05e7e7887820e2f9f1be87748b1070f29b6d2669e67457a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2036682af9b07a67118b6e427db098b0644a44719f7f95d80d69c96caa9ac6a8662002430dee08d604b33204a32fc7a47cb1e9c19c43c430abb4213c645a28eaec63201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d65353d3abcd19cf1a06dd235788ecb77f16a4ad84f8c5e8e0febb295d124d1320787d5c91de4a7f779bb06be78c987c402cebf04fee3f7debb09046e6eb831353201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20008e0c9bc3689c7ecbed26801427fd10295628d8ad06d437f00703e0651d8b3a20524fd0acf065d3b9b5cada86bb28e3a08b08c7a8ff42cfd224944a20fe33ee45201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20cc5e1958b661d4fc83750e29161fb8de216441c3749ebe92a7c465f439ae694420c2ba2d8509938a16e4cb5c05c01ffbdaab5f43c4984a835c1ed483815ea9ef06201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20b82ee30283bd763803ae07f4221d3f865fa32ca4d41b46c94ca68656f9d5296020388082d4718763c7c8378fc8826b67aaa5ffebd0511d221acdb13aaa90a9e355201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20c606436619880447c01fff0c8f8b3695bffe50de1b2971ddedf9b74b8628ba5c20ba93220db492071658588e7cbc1e77a3150e830b6a39901694884c6882fe7a6a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ca8e0e658169425043deeb758af5fe80c7b871a4cd743835065e139a4278d01b20826d19a290d3841d05fd47382a257ea514d95f6f4b75afc6b6b95b927ff36312201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20809911b0ba1b921fa0f9666be358137c63cfaba0e6aacc98aa35273b553bef5a2056f49b1832078b2d5fd612247918733515c74a50630f32c554adfde5e0b02b07201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d4bbc4f0416712c2b9a98084348e577255b44d8a8060e4ee7d91bee89b72e02b20d6bdbafbe87746a8f34367fbbd54a210cc031b1ceae5485b90a2a1abf3736d66201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207ef8010d3c8540f725bcf91b3cb011507a95afb77dc473083a7f84724aeed66020daa34a284f58eeabed22f2dc69ecacbceaa4047096f27940d3d1a849e00fa14c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20600b67aa12c4359a6f267692f8fc77c2e38991d7313c9b77e3af41bf91c601672072bb1e8f5d809614b79fb6714e9796e67ee2f3a5409394a03e7e41db6ec1d451201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d204e13fd65c313c28a10d2328aee4e25a19ef6b23c8debc70f8b5a92fb3177703720d655eafcbf666e2d72f04c35e4615e5f0e6894b1b16ce257c86bbfc19ba80401201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205eab8c22bededc809e904169b142dc83b4214d6b36dcec9cd04a6055db450a0020a02a2ffab4b0e8f283f59495d2440163a642e32e38f6d3d2fd75b609c9376355201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20de53a7a71c87a0f8ed39d346d2c9be022983a60b0b0e698ef6f33ff7a057f92d2030c52458c702f0cde4c7bd1a7aeecdf804b823371d347ae7343216af683eb64d201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d200eadd611a59195c473fe2a188ea3cc62eee223fe844ae4c7e59da5d566456c69208610b11d97a472df7f0f0d144a65d575066df51a18091c907e22bafc3758832500";
    // entry fun example_deser(breakpoint: u64) {
    //     if (breakpoint == 0) return;
    //     let stream = bcs_stream::new(XAMPLE);
    //     decode_contribution(&mut stream);
    //     if (breakpoint == 1) return;
    // }

    struct Session has copy, drop, store {
        enc_key: elgamal::EncKey,
        pedersen_ctxt: pedersen_commitment::Context,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        allowed_contributors: vector<address>,
        num_contributions_expected: u64,
        deadlines: vector<u64>,
        status: u64,
        /// If `status == STATE__ACCEPTING_CONTRIBUTION`, this indicates who should contribute now.
        expected_contributor_idx: u64,
        contributions: vector<VerifiableContribution>,
        culprit: Option<address>
    }

    #[test]
    fun deser() {
        let bytes = x"34201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d80578e00c4fe5c8db0764b0e5f921fcfccf62264dfa85151b15bf6a9d96e43120240b3fe85a16d548ba4e6007c9334224932e41d20de9d99b421356977f76793b201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2064596e40a51cab999886326cae6e03eba8a71921e526ffc9957e55251d1f410c204a2dd43e53187424ad882a3167d809f2dd1ded899d085c9ec6103025b914b50c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207a234f45fe50de29a0ce40e01aed93b9171d76aea34b5464ad99b11529df260920726215288aa50c1d739cdc0445f72d557bc07cfef7beb0ba337f7afa5f5dbe11201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20408706723241063a22aae5cac23972193537cac7329b39cf3742cbc2a6f7d86c201a5dda0944d449f4773efc0b703d79090f0f7c650bb9877d0bf0e04e64c01656201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d4c2cf839428678be1be51b49d183e31f117610f841885032c123c58d6a98b7820ee43592f98d94f0ca01381417b125b16216efc2551c9cbe39005b2792eada41f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209222a70c6ddd518e59cf28b8451700f755abb9de02cdc10180a03e7f5a4f29692026ccd5fe2e74017d22e5f5d6413eefffb1be2fdab83c7aa1bffcd0000fa0d00a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20e0b35d9c7ae455232aa41bd184ed4bfb55070765b702004292da1c1cdbae1549209ee590ab0c6191c5ac5e4e10416a0f434095d8e575551ee805c966d193698e1c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d201471e7cf1f9f7124501c5221b5e76ac11846ce1b87ac848ea589b0cc58ff3641201001088aaf6e5397cbc0a044b6859d4a3da98201d00d8675b96b4edd9febb009201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20a0af866f04fd79960416c7aba9ef33d1bbd0953d205c473f498377d8d53ec77c20406323a711b904a77d7973393b114d479eac9685b0f472ffd2f87161025cb700201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202084c347e99d2be9d1665fa66268a01800397858242c7e7c11a9781fa5f14952209474ea0952ea16b0c92e5c20a0d5cd74f001218e9b11307cee9c717c4c73b629201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2008204fb6d21aca04e00d5e1711416e380ea1e16e834a986c2cbd62731fe65c4c20e02a3ed6ae7ac7e38cbb411863c2bf7e6f61e71bfc51ff40843a5a7a692f0e5f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20221ddec46431af52601d816ba28103235ffa4591b98b2ddb1e9362b5976831542060605cf7e442d75e1df8a5b74981dd225dd9ff8b3b7e64b630da7cf1d915c24a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d206e021beeb13173cd2b9e21756543578fec7b41a8abce001f0651640447175340208824cb7ab5ad18aeeaebd7066efc374213b962021040507fa05f81a3a3c71624201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d203c991be79195e213c3bfc4dd375aa65f38af2b4355e3fb2f1756047d6e8f9c122066858b68831a46d0046b389f59536a33bd39698f21e6e8030a0ee75fb349c34c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207e7b040e7267d9125ba22541deaffb6aed12001145ee0e89eabde793d776833c20de8b8780a4f7aaac080813be5f71a292167eecb4243e216a51db1aee19d5e323201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d208e7c9608252eca2767d0e82a72c759d7a2acaf4f2cadc4be16b5b07a6661b60f20727ca0e031def7a47563ad466114c8224a54713416fd2b6f78be66c62ca64b64201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20f2997cafe6215ebf1cb2844494ec7fe218d1d14a200728c3066ecaba1098326720068b7a7dc78dc34329490e2ade25e666a8e18b56ed676e796fed06bb252a8b39201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209c08980fa75099e1f736a05ca8067e371200a82dc2389c913a28bee4db95fd5a209c344cb0abb784303304b584721fac934237a792ef01c28f05b9f1ee3cfa4308201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20aaa79e298d21acf11d2b3eb3b1b218b5af4f82e390829a86df93feeb10cf917220d0ad381f21c38ef6b6de73567d2c5b70b543ce17a41ef77d6cf3fc0642d99f0e201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d206c96230c383c6b1e7c41666612c09a43898e34607b859a3e6ec1e1f18e58c74f2040935aa100e8561a51385d6c8acd19f611c81b9406a09d5f5433f3215d295527201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d204635f18340703c4a8e5902c057e8169da97ce0ded296a8914ca735294a0a8e4f200e82ae048a1af5dea7d4ac91afe2d38e9d527fdd59c4dfc504ab09448668ad3f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20a6b2feec2aa76822024c4d785dadc46aacd779d46373d5e9090d2623b026040920204250aeb63936131c4067d499a3dcd0cfcfd4342e135d96fc2e8a96b5e7e60d201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20c0dc4ac50738c41f1c2929514a27ecf1f6d5da64e25944a79f02dcf3a7811d102000d8e9d5e4ff2e1bbe03e3c41ec0b329828732d1fc58121a005f150906176041201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2064591e3c00d4329199c18bbb5b43b47508156fffd4db1688390f5a093c9f02362002ef25e7b10222a335ac36bba92785615de070c3626b70685a3a18502b2f770a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d224d884f45a426b5fa52b36618a8aa9b84f9848d4bcea41d92c6e134579f57420cc93ebcf1d4cb545a01bb6faecc39e2230868421f49955f5ab0e16c566373f10201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ae25b267107b903d5390460565c3567a2d5efe4f863d6a00144670dbb542e2642094d127b4dde113544ad88b7d49ada2b7f879af6a4d515dab41d5e3651eb55228201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202ee91f1ced4d521bdfc60e448bec1989b952324effe1b008287715750620432c20b626a8e7d19ec92bc19ee021b626a6702a8cbe4f8110678d965d468460b06762201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2032c17bd42ff10cdd45a619ac002fcaa698500115479ab49c47908d6c33056c57206a5cb4d2d9a89bd56c238ef3418f5785784ac01e7e60a4f636353b8b3aa8071f201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2040af58aabb26e0b00088ea61fc22486b66cca835ebdf36a126641549cd6a7a662044672b80efa73471150626646fae0e1fc8f2d0f56d5f540aedcfab2cebee2d67201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d202288e60c6fafb365a5d3837deeb9fd615936a3baa613b0037c93e6f553f60c21208e82d6ff01e4fb19a5171e51f2f70f76b8478f161be58cf3a49551e1ff833e44201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ae7154f6b7001de249e771f53cf21c7d5545bd401ea3f1bbb21bee835810380b20a0c6412f8c543f5140bfb2402ed102f59a16b77bdb261a31e96b1796bfab2478201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205a368373de62007eb64258aa2dad3db0f83f4a04a7a0e497083b9118dbbf884c20be95d3580c127f049811d9e21c6987aefec510bcbe3696491d7babc3974b6c03201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d209258035f90853a3d15d5323c6865345c29aa5b54cc7b18e1cdc08e7aa6255d20204874b6dd11c1fcb27dae45bcb5d7ceae4ecac976aab6283b2746c80581fb6a54201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d201c600d557b6cb48baf5985ab49824954ac86fdae77ee4dc9a1629717f333032b20e4a967c4647aa5f4030eda6b1dbfc0f7c46edaf7f960c1fe8dc0a4b454586616201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205230d663e5a0b468600d7d07afc615bb93e295d59fbc166a67e1d1c480eb4d7920d8a469f338e837697002fad72244abe3b8c9f4992d408d80aba74db98eb75a70201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2072ecd17bf84745b4ee2339ccd89b714286c80bf1d4d68cb0585813f8b8765a62205478697f9c8b4c96a3c72da7527a1128692bec3dac2982a154ea4f8039cafa22201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2044e46466e1b1144c44f441db3a2560c60294318c22db262fa55c1152fbe31961203eb7e8fe5329ab2df05e7e7887820e2f9f1be87748b1070f29b6d2669e67457a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d2036682af9b07a67118b6e427db098b0644a44719f7f95d80d69c96caa9ac6a8662002430dee08d604b33204a32fc7a47cb1e9c19c43c430abb4213c645a28eaec63201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d65353d3abcd19cf1a06dd235788ecb77f16a4ad84f8c5e8e0febb295d124d1320787d5c91de4a7f779bb06be78c987c402cebf04fee3f7debb09046e6eb831353201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20008e0c9bc3689c7ecbed26801427fd10295628d8ad06d437f00703e0651d8b3a20524fd0acf065d3b9b5cada86bb28e3a08b08c7a8ff42cfd224944a20fe33ee45201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20cc5e1958b661d4fc83750e29161fb8de216441c3749ebe92a7c465f439ae694420c2ba2d8509938a16e4cb5c05c01ffbdaab5f43c4984a835c1ed483815ea9ef06201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20b82ee30283bd763803ae07f4221d3f865fa32ca4d41b46c94ca68656f9d5296020388082d4718763c7c8378fc8826b67aaa5ffebd0511d221acdb13aaa90a9e355201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20c606436619880447c01fff0c8f8b3695bffe50de1b2971ddedf9b74b8628ba5c20ba93220db492071658588e7cbc1e77a3150e830b6a39901694884c6882fe7a6a201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20ca8e0e658169425043deeb758af5fe80c7b871a4cd743835065e139a4278d01b20826d19a290d3841d05fd47382a257ea514d95f6f4b75afc6b6b95b927ff36312201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20809911b0ba1b921fa0f9666be358137c63cfaba0e6aacc98aa35273b553bef5a2056f49b1832078b2d5fd612247918733515c74a50630f32c554adfde5e0b02b07201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20d4bbc4f0416712c2b9a98084348e577255b44d8a8060e4ee7d91bee89b72e02b20d6bdbafbe87746a8f34367fbbd54a210cc031b1ceae5485b90a2a1abf3736d66201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d207ef8010d3c8540f725bcf91b3cb011507a95afb77dc473083a7f84724aeed66020daa34a284f58eeabed22f2dc69ecacbceaa4047096f27940d3d1a849e00fa14c201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20600b67aa12c4359a6f267692f8fc77c2e38991d7313c9b77e3af41bf91c601672072bb1e8f5d809614b79fb6714e9796e67ee2f3a5409394a03e7e41db6ec1d451201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d204e13fd65c313c28a10d2328aee4e25a19ef6b23c8debc70f8b5a92fb3177703720d655eafcbf666e2d72f04c35e4615e5f0e6894b1b16ce257c86bbfc19ba80401201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d205eab8c22bededc809e904169b142dc83b4214d6b36dcec9cd04a6055db450a0020a02a2ffab4b0e8f283f59495d2440163a642e32e38f6d3d2fd75b609c9376355201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d20de53a7a71c87a0f8ed39d346d2c9be022983a60b0b0e698ef6f33ff7a057f92d2030c52458c702f0cde4c7bd1a7aeecdf804b823371d347ae7343216af683eb64d201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d200eadd611a59195c473fe2a188ea3cc62eee223fe844ae4c7e59da5d566456c69208610b11d97a472df7f0f0d144a65d575066df51a18091c907e22bafc3758832500";
        decode_contribution(&mut bcs_stream::new(bytes));
    }

    public fun dummy_session(): Session {
        Session {
            enc_key: elgamal::dummy_enc_key(),
            pedersen_ctxt: pedersen_commitment::dummy_context(),
            initial_ciphertexts: vector[],
            allowed_contributors: vector[],
            num_contributions_expected: 0,
            deadlines: vector[],
            status: 0,
            expected_contributor_idx: 0,
            contributions: vector[],
            culprit: option::none()
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        enc_key: elgamal::EncKey,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        allowed_contributors: vector<address>,
        deadlines: vector<u64>
    ): Session {
        let num_contributions_expected = allowed_contributors.length();
        assert!(num_contributions_expected >= 2, 180007);
        assert!(num_contributions_expected == deadlines.length(), 180008);

        // Ensure deadlines are valid.
        assert!(timestamp::now_seconds() < deadlines[0], 180009);
        let i = 1;
        while (i < num_contributions_expected) {
            assert!(deadlines[i - 1] < deadlines[i], 180010);
            i += 1;
        };

        let num_items = initial_ciphertexts.length();
        Session {
            enc_key,
            pedersen_ctxt: pedersen_commitment::rand_context(num_items),
            initial_ciphertexts,
            allowed_contributors,
            num_contributions_expected,
            deadlines,
            status: STATE__ACCEPTING_CONTRIBUTION,
            expected_contributor_idx: 0,
            contributions: vector[],
            culprit: option::none()
        }
    }

    public fun state_update(session: &mut Session) {
        let now_secs = timestamp::now_seconds();
        if (session.status == STATE__ACCEPTING_CONTRIBUTION) {
            if (session.contributions.length()
                > session.expected_contributor_idx) {
                session.expected_contributor_idx += 1;
                if (session.expected_contributor_idx
                    == session.num_contributions_expected) {
                    session.status = STATE__SUCCEEDED;
                }
            } else if (now_secs >= session.deadlines[session.expected_contributor_idx]) {
                session.status = STATE__FAILED;
                session.culprit = option::some(
                    session.allowed_contributors[session.expected_contributor_idx]
                );
            }
        }
    }

    public fun process_contribution(
        contributor: &signer, session: &mut Session, contribution: VerifiableContribution
    ) {
        let addr = address_of(contributor);
        let (found, idx) = session.allowed_contributors.index_of(&addr);
        assert!(found, 180100);
        let num_contri_committed = session.contributions.length();
        assert!(idx == num_contri_committed, 180101);
        let trx = fiat_shamir_transform::new_transcript();
        let original =
            if (idx == 0) {
                &session.initial_ciphertexts
            } else {
                &session.contributions[idx - 1].new_ciphertexts
            };
        if (contribution.proof.is_some()) {
            assert!(
                bg12::verify(
                    &session.enc_key,
                    &session.pedersen_ctxt,
                    &mut trx,
                    original,
                    &contribution.new_ciphertexts,
                    contribution.proof.borrow(),
                ),
                180102
            );
        };
        session.contributions.push_back(contribution);
    }

    public fun succeeded(session: &Session): bool {
        session.status == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.status == STATE__FAILED
    }

    public fun get_culprit(session: &Session): address {
        assert!(session.status == STATE__FAILED, 175225);
        *session.culprit.borrow()
    }

    public fun input_cloned(session: &Session): vector<elgamal::Ciphertext> {
        session.initial_ciphertexts
    }

    public fun result_cloned(session: &Session): vector<elgamal::Ciphertext> {
        assert!(session.status == STATE__SUCCEEDED, 175158);
        session.contributions[session.num_contributions_expected - 1].new_ciphertexts
    }

    public fun is_waiting_for_contribution(
        session: &Session, who: address
    ): bool {
        if (session.status != STATE__ACCEPTING_CONTRIBUTION)
            return false;
        who == session.allowed_contributors[session.expected_contributor_idx]
    }

    #[lint::allow_unsafe_randomness]
    /// NOTE: client needs to implement this.
    public fun generate_contribution_locally(
        contributor: &signer, session: &Session
    ): VerifiableContribution {
        assert!(session.status == STATE__ACCEPTING_CONTRIBUTION, 183535);
        let contributor_addr = address_of(contributor);
        let (contributor_found, contributor_idx) = session.allowed_contributors.index_of(&contributor_addr);
        assert!(contributor_found, 183536);
        assert!(session.expected_contributor_idx == contributor_idx, 183537);

        let num_items = session.initial_ciphertexts.length();

        let current_deck =
            if (session.expected_contributor_idx == 0) {
                session.initial_ciphertexts
            } else {
                session.contributions[session.expected_contributor_idx - 1].new_ciphertexts
            };
        let permutation = randomness::permutation(num_items);
        let rerandomizers = range(0, num_items).map(|_| group::rand_scalar());

        let new_ciphertexts = range(0, num_items).map(|i| {
            let blinder =
                elgamal::enc(
                    &session.enc_key, &rerandomizers[i], &group::group_identity()
                );
            let new_ciph =
                elgamal::ciphertext_add(&current_deck[permutation[i]], &blinder);
            new_ciph
        });
        let trx = fiat_shamir_transform::new_transcript();
        let proof =
            bg12::prove(
                &session.enc_key,
                &session.pedersen_ctxt,
                &mut trx,
                &current_deck,
                &new_ciphertexts,
                permutation,
                &rerandomizers
            );
        VerifiableContribution { new_ciphertexts, proof: option::some(proof) }
    }

    #[test(
        framework = @0x1, alice = @0xaaaa, bob = @0xbbbb
    )]
    fun example(
        framework: signer,
        alice: signer,
        bob: signer,
    ) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);

        let enc_base = group::rand_element();
        let (dk, ek) = elgamal::key_gen(enc_base);
        let plaintexts = vector::range(0, 52).map(|_| group::rand_element());
        let ciphertexts = plaintexts.map_ref(|plain| elgamal::enc(&ek, &group::rand_scalar(), plain));
        let now_secs = timestamp::now_seconds();
        let session =
            new_session(
                ek,
                ciphertexts,
                vector[alice_addr, bob_addr],
                vector[now_secs + 5, now_secs + 10]
            );
        print(&bcs::to_bytes(&session.enc_key).length());
        print(&bcs::to_bytes(&session.enc_key));
        print(&bcs::to_bytes(&session.pedersen_ctxt).length());
        print(&bcs::to_bytes(&session.pedersen_ctxt));
        print(&bcs::to_bytes(&session).length());
        print(&bcs::to_bytes(&session));
        assert!(is_waiting_for_contribution(&session, alice_addr), 185955);
        let alice_contribution = generate_contribution_locally(&alice, &session);
        process_contribution(&alice, &mut session, alice_contribution);
        state_update(&mut session);
        assert!(is_waiting_for_contribution(&session, bob_addr), 185956);
        let bob_contribution = generate_contribution_locally(&bob, &session);
        process_contribution(&bob, &mut session, bob_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 185958);
        let shuffled_ciphs = result_cloned(&session);
        let shuffled_plains = shuffled_ciphs.map(|ciph| elgamal::dec(&dk, &ciph));
        let permutation = plaintexts.map(|plain| {
            let (found, new_pos) = shuffled_plains.index_of(&plain);
            assert!(found, 185959);
            new_pos
        });
        print(&permutation);
    }
}
