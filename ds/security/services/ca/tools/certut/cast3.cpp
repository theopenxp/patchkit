
// cast3.cpp

#include <pch.cpp>
#define EXPORT_CONTROL DOMESTIC
#include "cast3.h"
#include <string.h>
#include <stdio.h>

/* CAST S-boxes */
#pragma region sboxes
const unsigned int S1[256] = {
    0xc6b00b1e, 0xd08d094d, 0x959cb449, 0x8d531db4, 0x4be173c6, 0x5768439b, 0x128a2452, 0x0f3ff37a,
    0xd13e2600, 0xcd088c51, 0x8e296754, 0x9f7f55ff, 0x5faef124, 0x4ed3e8bd, 0x08a43a43, 0x1b77f7fb,
    0xc0a9ed79, 0x7281c4b7, 0x4b776caa, 0xff75ab5d, 0xf91a4cf9, 0x4a7a7a4d, 0x71514583, 0xcbd5d1d5,
    0xcaa98800, 0x7576516c, 0x4150fdfb, 0xfb37f9fa, 0xf657b43f, 0x4f3ff3ef, 0x7c612b9d, 0xcf7ffdfb,
    0x80ea38a2, 0x68922405, 0xda4fa8f7, 0x3c8a46c1, 0xd21cdbce, 0x3194b822, 0x8498a509, 0x666378af,
    0xb05d8ac2, 0x5264708c, 0xe8dff3ba, 0x07c9c831, 0xe359af3f, 0x0d6fabfc, 0xb5a05a25, 0x5977d3f8,
    0x890c5e39, 0x84a28601, 0x8b67ff16, 0x80ac9028, 0x88e79bf2, 0x854511f5, 0x8f7fb425, 0x8b76c5ff,
    0x6bca5bc1, 0x6bd93db0, 0x679a19e8, 0x627efbcb, 0x6d5f6ad8, 0x6abfdf50, 0x66a6c4f9, 0x6b7fb9f8,
    0x851ac1cd, 0x539ee5ca, 0x3fa7791e, 0xee4adaa3, 0xb0da1081, 0x64722b5c, 0x0180ed45, 0xdd7d3aa9,
    0x03286987, 0xd66be246, 0xbdc2aa87, 0x6cc198bc, 0x3c263a67, 0xec8925ba, 0x83bed710, 0x586d1abc,
    0x8ab38c7e, 0x71898970, 0xe87ca369, 0x1d254b1e, 0x0b7d85ba, 0xf92f979a, 0x6b618a40, 0x986c1e92,
    0xc99ac587, 0x3e1e14ab, 0xa2aa30b8, 0x586432ad, 0x44497b78, 0xbd6536bc, 0x273fc5ca, 0xdc6530bc,
    0xc3ee7b71, 0x8b904102, 0x005567f4, 0x4f918356, 0xf8abbe8d, 0xb2ded2e5, 0x36926a4e, 0x7461b37c,
    0xc2f5ce45, 0x8946951b, 0x0b15be3d, 0x443505f2, 0xf14de078, 0xbf3566fb, 0x3fba3326, 0x7a6d3ebf,
    0xc3b8b63e, 0xe7bb4246, 0x384d3281, 0x12fe72eb, 0x8b0c54b5, 0xa640fe22, 0x744f7db6, 0x588f08b8,
    0x28471d46, 0x00f0f3f7, 0xd44154ff, 0xf16f301c, 0x6edd219b, 0x48e51a03, 0x9cf8aefe, 0xb86574bf,
    0x8d06d47d, 0x491bf432, 0xa62a7926, 0x64c7daf8, 0x5a574491, 0x9cfe7ee5, 0x7b1cf91c, 0xb6a92e10,
    0x78ac797c, 0xbebeb314, 0x559ffa1e, 0x96cd88a4, 0xa63a2e77, 0x654535e1, 0x8932c728, 0x42e10a85,
    0x813f9826, 0x8b1599e9, 0x72e1a3d3, 0x76e14e07, 0x40a8918b, 0x43eac70a, 0xb2e5daf9, 0xb2610e8a,
    0x131fd57e, 0x16c20411, 0xeae620a3, 0xe2a12694, 0xddc56b61, 0xd6a92685, 0x2df394d0, 0x26e96085,
    0xc97a6fc3, 0xa104515b, 0xebd9278e, 0x851c83ad, 0xa3aeae9c, 0xca028754, 0x8d0e7a7f, 0xeff5a7e5,
    0xfbe9df9c, 0x91d2c5e8, 0xd149aec6, 0xbe79154a, 0x9ac9b069, 0xf6f97688, 0xb4362776, 0xd0e12e86,
    0xcabca364, 0x1d36537e, 0x20d17279, 0xf93a7752, 0x21510485, 0xfcd5aeba, 0xcccb2967, 0x12c21880,
    0x305a0c9d, 0xe86de2ec, 0xde0c0486, 0x0bea2485, 0xd6c97583, 0x03290a12, 0x3734fb8c, 0xe2e92486,
    0xc153e151, 0x75f7e74a, 0xf3ee4b8e, 0x4821e210, 0xae93d829, 0x101be9dd, 0x97e9cff4, 0x2b14183c,
    0x0545c904, 0xba2222fc, 0x398bc832, 0x8a8cba18, 0x6a4d1acb, 0xd8e00719, 0x5dd7d584, 0xee04183d,
    0xc4da06de, 0xd7e22bd1, 0x0e1593ef, 0x1b4e51bb, 0x7d30a737, 0x6f40d522, 0xb72aeac5, 0xae273e32,
    0xbfd36706, 0xa255be29, 0x76e3121f, 0x6e0d123c, 0x00245bd9, 0x1b0c1c29, 0xc9528578, 0xda0c523d,
    0x8581d3ef, 0x2df9cba3, 0x1e3c1772, 0xb9f8b9c5, 0x56e63420, 0xf6b7126c, 0xc0fb4ac7, 0x620893c9,
    0x86be64e4, 0x250fdf80, 0x1d7c1cbe, 0xb27a2776, 0x572200d1, 0xfb5c4470, 0xc1d3b18a, 0x6c043c3e,
    0x8ff7b49c, 0xf1d068c6, 0x9c044011, 0xe4976a6e, 0x3d45343d, 0x402fbe92, 0x28041f0b, 0x5ec42a38,
    0x7c28b5e5, 0x0cbbd354, 0x6228b66e, 0x170410ad, 0xcab4c13f, 0xbe8c30be, 0xd2956e74, 0xae0c163e,
};
const unsigned int S2[256] = {
    0xc2ad2c5e, 0x194d87b3, 0x82c127ce, 0x56bb0629, 0x688a0d7a, 0xb726d1c2, 0x21f3de43, 0xf4cd6b22,
    0x88c5295c, 0x5eba71a7, 0xcb14e9b7, 0x16b6d157, 0x24dc2fa1, 0xfa5958f5, 0x6b72774c, 0xbb2283d0,
    0x069d6a56, 0x83fbdc6d, 0x11c78559, 0x9d32faea, 0x16239af7, 0x9f7254a5, 0x0618cfa8, 0x83d22ba1,
    0x508f6b36, 0xde7acca9, 0x447b55a7, 0xc75ad1a1, 0x41475489, 0xcf33d385, 0x57b890e7, 0xd110d7a1,
    0x61152b5e, 0x38882409, 0xd9ac7bdd, 0x88258fbd, 0x2659d784, 0x75568779, 0x9616f2b3, 0xc805baaa,
    0x01c014da, 0x55670ac4, 0xbfc6df20, 0xe732d018, 0x4ff1eb6d, 0x1d72f223, 0xfc6b158c, 0xa7b3fe37,
    0xa4aaa246, 0x549d7b56, 0x6d3a1124, 0x93107081, 0x597c701a, 0xaba2f99c, 0x966ed435, 0x6fa506d5,
    0xc805995f, 0x3304b3b4, 0x0739aba1, 0xf662d3ee, 0x3be6a0a9, 0xceb8822e, 0xf732c5b5, 0x0d3e5645,
    0xcb70db1c, 0x40d450f7, 0xb358b096, 0x3ea2f1f9, 0xa1479a2c, 0x2fbb2e31, 0xd8ee0991, 0x55d05cf0,
    0x29d8fe9e, 0xa777e6e6, 0x53591efc, 0xdf2b260a, 0x4d05f86b, 0xc3c407a3, 0x326fc08c, 0xbbef3432,
    0x0e505514, 0x12262b00, 0xb99a5217, 0xa4af05ab, 0xc7faa510, 0xd73f23c7, 0x7e513060, 0x6a4bb4e7,
    0xd1123474, 0xcfe33bff, 0x65e6eae9, 0x7ed726c0, 0x115a0beb, 0x062e24e5, 0xafa567b7, 0xb88da0e3,
    0x684cdc1c, 0x5911bb51, 0x0035c48d, 0x303c784f, 0x4fd460d6, 0x7dcb70aa, 0x2f8b2d63, 0x195ccd68,
    0x9059cb18, 0xa4aad589, 0xff8b0863, 0xceaf2777, 0xb66814a3, 0x84efa545, 0xd5f6a24e, 0xe73a09d5,
    0xace39d04, 0xfd40c427, 0x3d67ee62, 0x6a8d8fe2, 0x78e56ff9, 0x23ef86de, 0xeea723ff, 0xb678d983,
    0x891cce1d, 0xda9d0cee, 0x1ea434e7, 0x4fef24bd, 0x5bbbd7cf, 0x07a57d7e, 0xcfaf32e7, 0x94e76107,
    0x69f7a056, 0x427b29bd, 0x69fd88cc, 0x4f858823, 0x37e3a276, 0x181c52ca, 0x38e1754b, 0x19d5e52a,
    0x63fe8254, 0x45d8ddad, 0x645e65b7, 0x4d8c5f11, 0x3da381a1, 0x1541fcf9, 0x3248f846, 0x16610998,
    0xaffeed5e, 0x4c89506b, 0x5a9d2a5d, 0xb6027ee0, 0x695f19fb, 0x8430dead, 0x9d564aaa, 0x7cee8dad,
    0x1bb5cf3e, 0xf54445a5, 0xef49d2a3, 0x0c505deb, 0xde54f681, 0x340a5d8f, 0x2c811eed, 0xc80859e9,
    0xca43a756, 0xc3b6870b, 0xa292fcd7, 0xa11b01b5, 0x6f505c8c, 0x6e4c0c71, 0x0f2450b9, 0x077b34a2,
    0xcaf7b6d2, 0xce2eabc2, 0xa0ad7228, 0xac085e5c, 0x60ee6869, 0x66695e2f, 0x05529a84, 0x0896747f,
    0x0dc5254e, 0xfbe7fa5c, 0x96629628, 0x6820f489, 0x1060d712, 0xe4c07b94, 0x8d005835, 0x72ffa0d9,
    0x33333457, 0xc81137b4, 0xac2a0dad, 0x5d685fa6, 0x22952fa5, 0xd1820424, 0xbc084bbd, 0x4640d80d,
    0x6fd5a8eb, 0x241d0106, 0xa79be06b, 0xe863800c, 0x51d1cadf, 0x1f7e52c6, 0x9e035d66, 0xd7372d07,
    0xdd1caa69, 0x93eab513, 0x13ec6d03, 0x5bee57b3, 0xeb85a994, 0xa3235c50, 0x24aab079, 0x69534185,
    0xa8cc2de3, 0x42ab58f9, 0x3d3f02ec, 0xd0607e5e, 0x9779d9e3, 0x73825630, 0x0ae04a9d, 0xea88ed14,
    0x65d76f83, 0x8b224d0c, 0xf12b9212, 0x1a225575, 0x51b6561c, 0xb2e85510, 0xcb631642, 0x2e6ad154,
    0xcce5afeb, 0x7dd0e7ac, 0xa4f4bc78, 0x16fd09b8, 0x39221421, 0x892e045d, 0x59467096, 0xe9ddbc9f,
    0x549196ef, 0xe01c8b70, 0x3f1f5a94, 0x8a6a56cc, 0xa6886858, 0x100bf6b6, 0xc330d2b9, 0x77e07c62,
    0x0a73e5f3, 0x2dc5bad2, 0x29c09691, 0x0e42f415, 0x8e06370e, 0xa372fb29, 0xaa365000, 0x84dd8070,
    0x9dd59cea, 0xbe777711, 0xba486d14, 0x9b1a570a, 0x1d37a73c, 0x3760048b, 0x3b6a4310, 0x106610b0,
};
const unsigned int S3[256] = {
    0x86f5c342, 0xc231da03, 0x64140aed, 0x129ec99e, 0x3ef407ec, 0x6fcb995f, 0xe0382359, 0xb9ba0244,
    0x72524815, 0x3a759e48, 0xb3491e6d, 0xcb8e4b5e, 0xe61bfda2, 0x91ec2964, 0x27dee3ca, 0x5a3ad1fe,
    0x22bdbec0, 0x2dc09f7a, 0x0cdf5081, 0x12ea514f, 0x99f9ae94, 0x980a4411, 0x8fc26e5a, 0xa58ac137,
    0x47aa9b46, 0x6b132788, 0x60e5aa94, 0x5fba6f72, 0xd95ebb20, 0xd14249b8, 0xfabb0177, 0xdbb2ef5b,
    0x07e182db, 0x73c6cdd8, 0x6777b8e8, 0x0b91adb8, 0xf457a25b, 0x842d2285, 0x8998d5b3, 0xdbd06aa2,
    0xbd2bd4d0, 0xe438849d, 0xde35b50b, 0x9d49e649, 0x59a24077, 0x2ec75a8e, 0x1b16c97d, 0x4cefb517,
    0xa8560728, 0x94c66e8e, 0x7c4d1ac9, 0x7b1ad37a, 0xdea5f3ad, 0xfd1d191b, 0x13936002, 0x311f4f3d,
    0x232cfff2, 0x1dafdb72, 0xde68f9bf, 0xd9822476, 0x4b18fe7b, 0x4098dc82, 0x9382d372, 0x9b986d5e,
    0x02bc173a, 0x56211e7b, 0x208c9e97, 0x465edfe6, 0x7a2c93d6, 0x2b8a9d67, 0x44b125e3, 0x3d7ad47c,
    0x7352cced, 0x3ac4caa2, 0x52908857, 0x0b475f24, 0x32837b58, 0x553cafdc, 0x33dff722, 0x5e034584,
    0xa72d38b8, 0xd9a959d0, 0x680684bb, 0x37738535, 0xd9286aae, 0xb8d21069, 0x2f5af870, 0x7573554f,
    0xe6e30fbe, 0x8a4331f2, 0x30343cae, 0x5f6bfb08, 0x8dd72f98, 0xd51bdf40, 0x5e6ac50d, 0x1f7b7b21,
    0xa23856a3, 0x265f49a0, 0xb3ffbcd2, 0x1f517bc0, 0x704f34a1, 0xc064a63d, 0x4d514109, 0xcf91bc9a,
    0x5dbb5028, 0xe5801277, 0x6ffc3171, 0xdd003233, 0x8dfac44d, 0x2a9fdeb6, 0xaf57cd95, 0x18d7216d,
    0x0c568150, 0xa126e824, 0x48845eb3, 0xde83c700, 0x1eb43557, 0x9dcdcde3, 0x534b6428, 0xf167db45,
    0x63f56b0a, 0xfdf60f08, 0x1ea97dc5, 0x99d3700c, 0x5f516803, 0xc44948fa, 0x17130708, 0x8f50f924,
    0x3e6c3e77, 0xb2fc2237, 0x9c5fdeda, 0x2283b18f, 0x84fffbfa, 0x1f54c56f, 0x10617eea, 0x89a3d770,
    0x8b8bb8a0, 0x021ae3ca, 0x0a40eb7b, 0xb9931a68, 0x1c520414, 0xa9e5d4d1, 0x9f07974e, 0x20d709e8,
    0x9bf44ad1, 0xdd7b42dc, 0xbcd4acb6, 0xe3a3ad7d, 0xe3f45286, 0xa0011424, 0xff8b9678, 0x95a33d06,
    0x363747d2, 0x589a529b, 0x1ae856a6, 0x65b39345, 0x61014390, 0x21cbb10c, 0x42b2d541, 0x23ab136d,
    0xb6ea7bef, 0x828935cc, 0x572cc4da, 0x7b8c55ad, 0x06985ecd, 0x3cb6de11, 0xf9810104, 0xeb49ba96,
    0x8d602160, 0x9d55583b, 0x672c491c, 0x67d4367f, 0x232fb845, 0x164aa69b, 0xe38f95f9, 0xf6026905,
    0x188df738, 0xadffb308, 0xc4564efb, 0x4253af4c, 0x646c0f3f, 0xcd12e98a, 0xab9a1124, 0x01b6b60c,
    0xdb232663, 0x67240f45, 0x24750c8c, 0xa30b5941, 0xbb83074f, 0x30952596, 0x63cb2f44, 0xe381956c,
    0x85da15f0, 0x591319b0, 0xe738b55f, 0x09bc5808, 0xbfd8903f, 0x64ea3ea8, 0xcb1787af, 0x329cfeb7,
    0x3574c3a7, 0xfd5448df, 0x546682be, 0x86a5f1ed, 0x37357d11, 0xd2caad96, 0x74f97c59, 0x9b11626d,
    0x219b3356, 0x96ed7b89, 0xa7f28773, 0x39c586f8, 0xdcda6943, 0x7f26bfa3, 0x60ecffad, 0xfaa55681,
    0x28812cd5, 0x8635bb1e, 0xb5c63f63, 0x1a9df8c0, 0xca7728d7, 0x5a6dd80b, 0x599ceec4, 0xd89d78e8,
    0x2ccc5068, 0xe8ef4e4b, 0x3c5b3f1f, 0xd0b37c2a, 0xbd7f37c8, 0x4700a556, 0x82b76a41, 0x40f79351,
    0x120f5a67, 0xe312312e, 0x291a3299, 0xd8621dfa, 0x8888c380, 0x6deddd5c, 0xa8316eee, 0x5dc50280,
    0x83728ebf, 0x67e0ca5d, 0x0f60f57e, 0xd83544c9, 0x9b82363a, 0x523dc28d, 0x14bdeaf1, 0xfe31dd8b,
    0xe4054d64, 0x388224c0, 0x5b4b7709, 0x9ca5f2c4, 0xd0356ec8, 0x0bbb4e11, 0x58a504c1, 0x88b6fee9,
};
const unsigned int S4[256] = {
    0x154b0bc2, 0x9e92acd6, 0xe8d3562e, 0x607b3270, 0xe148e878, 0x7f97f0d6, 0x18af89ad, 0x8cb5df89,
    0x4a28e9c0, 0xcf75d66f, 0xaab7d57a, 0x3cb2462b, 0xb5503fbb, 0x3db35e39, 0x558ba589, 0xc784e535,
    0xf190ac77, 0x278b7320, 0xae647e1f, 0x7f8f5d12, 0x6814f368, 0xbfea6e26, 0x264d12e3, 0xfff7fe37,
    0x204229c2, 0xf8175a3f, 0x7eb95eff, 0xb135beec, 0xafbd2e64, 0x6eb5fe17, 0xe4d0f00b, 0x3bb53e56,
    0x804a28e9, 0xe74801c9, 0xd535853d, 0xa34026c6, 0xd16d31a0, 0xb20c9b68, 0x9bd07dfc, 0xe072d02f,
    0x68cc31a2, 0x016ccf1d, 0x3e970216, 0x566919c6, 0x2f8c62ff, 0x5af7fe3f, 0x622e2a72, 0x1fbfde1d,
    0x636e0fa0, 0x49aa21c0, 0xd7bed210, 0xe88c49bb, 0xe7f155bc, 0xddb50597, 0x5931665e, 0x7f370e7e,
    0x7559715c, 0x51f5bcb2, 0xdea5f68f, 0xffd6e11e, 0xfaa10c2c, 0xd6355e1e, 0x5f76ff1c, 0x7f89fa91,
    0x9a14227a, 0x90de812a, 0xd70faf92, 0xd7a79f88, 0x1e94d1c1, 0x0150192e, 0x4ef2a450, 0x53eaf634,
    0x3df59079, 0x20b8ff96, 0x6563fcc6, 0x6b7d7fd7, 0xa39e8607, 0xa36f7785, 0xf357c830, 0xe84bdc8d,
    0x7fd485cf, 0x78579ad9, 0xc0b2d7a7, 0xc15b64ea, 0xfe4b8a91, 0xe02f47de, 0x509bfb5e, 0x402b938b,
    0xa714903a, 0xbf437783, 0x016d7343, 0x06614715, 0x386b179d, 0x3169d7af, 0x9a860db2, 0x846117ae,
    0x0e960151, 0xf9042c75, 0x8aebfc85, 0x7c948b3a, 0xb7b25818, 0x44c3f6d0, 0x250f0044, 0xdf2dfdd6,
    0xbe90485b, 0x5ea962a4, 0x314b2fae, 0xc9ae207e, 0x00438b42, 0xec2bd783, 0x8c7a93ce, 0x7070e3e1,
    0xeca92618, 0x8676c879, 0x996afbac, 0xfe507047, 0xa8ad7c44, 0xca78a82f, 0xc765dfa6, 0xa0eb6786,
    0xd38ec8e4, 0xa6a9154e, 0xa179df37, 0xc08a18a3, 0x947665d4, 0xe1e977a6, 0xe9a8d6a0, 0x805dd72d,
    0x67170782, 0x29cc85b6, 0xfa09f946, 0xb685b898, 0x17b2eeb9, 0x4c437d1e, 0x8fd5a2ce, 0xdae9d860,
    0x1ed6e781, 0x59abd226, 0x9841d998, 0xc86e604b, 0x648cb1d9, 0x28695051, 0xe655a748, 0xb178e057,
    0x86e6a39f, 0xb775dfe3, 0x19b0f07f, 0x2c595352, 0xff48fd0b, 0xc9386946, 0x77b99522, 0x4929f4dd,
    0x5416afa2, 0x6e41505f, 0xc86b543f, 0xe3433b0d, 0x396d2205, 0x1a6bf075, 0xb380786a, 0x8d631036,
    0xf5942429, 0x10160b29, 0x87edaa55, 0x75b6ae0e, 0x42953fc0, 0xa3d0b2a8, 0x2c287f9e, 0xd62ef34e,
    0xfbb23fe3, 0x17ba4cd4, 0x8c690a74, 0x62bd1d86, 0x5b50e4bc, 0xad2df05f, 0x31788532, 0xc943dff7,
    0x139a00c8, 0x1954ae83, 0x6068dc70, 0x7b5245db, 0xd5af537e, 0xc96fa6ff, 0xa847c89e, 0xa9e9201c,
    0x268df73c, 0x27ab3152, 0x487ff8cf, 0x4da846df, 0xe971086c, 0xe0eb5074, 0x88aedafc, 0x895fd079,
    0xf7b7d1c5, 0x587f57b5, 0xba2aff05, 0x1ea6ea9f, 0xf79128ff, 0x4d7b6b19, 0xa67770cc, 0x1a490e22,
    0x36f461c7, 0x89990420, 0x686a0fdb, 0xc05ea648, 0x2dbdf79a, 0x894a8612, 0x7f76350e, 0xc1482610,
    0x175d75d8, 0xd756c9e5, 0x8899a638, 0x4d729555, 0x76e87b0d, 0xa902bf41, 0xfe908360, 0x290a669e,
    0x0cbfe9a5, 0xd6ea821c, 0x8840867c, 0x4be83d0b, 0x7144e403, 0xba482632, 0xf2297a2c, 0x2d48c631,
    0x64b7f26e, 0xb1a5d96a, 0xc7cc2c12, 0x159dfc0d, 0x5bb5a987, 0x8ae020ef, 0xed08fdd9, 0x368e2148,
    0x9211b9e5, 0x57801e92, 0x3c4ad833, 0xe285dbc1, 0xab60f2fe, 0x640e261c, 0x00d3c371, 0xd9731df4,
    0x83a2d68f, 0x2977b8c5, 0xb1430a33, 0x127183d8, 0xe50c8579, 0x415df4b8, 0xc9ec8e99, 0x69cab61b,
    0xbfa5b17b, 0x0f086751, 0x885c2e88, 0x2d0b409d, 0xd8599e6b, 0x68c88633, 0xe18f0cbf, 0x4974023a,
};
const unsigned int S5[256] = {
    0x2bb1ce76, 0xa24f25c4, 0x831431d4, 0x0303db1a, 0x08db19f4, 0x8f32c2d9, 0xa9f21d00, 0x35f432ef,
    0x2cb25fbf, 0xa02e5aad, 0x8d95f281, 0x1aed8191, 0x17176c34, 0x915730db, 0xb2ea75b1, 0x3d48aae2,
    0x0f031db4, 0xd4ecade3, 0xcb717039, 0x196a7209, 0x91aa7df8, 0x48d732bb, 0x52c7ea11, 0x9048e28b,
    0xef394063, 0x347ee412, 0x38cac74d, 0xf874a625, 0x69d5909e, 0xb4cba299, 0xb46fa239, 0x608ea099,
    0x3d73d51a, 0x98daade4, 0xe6088fb9, 0x4e93582a, 0xc82ceda5, 0x7f8b52cf, 0x108ca1ee, 0xb81f4457,
    0x1f973404, 0xb7cb9a2a, 0xd20508da, 0x65667ee7, 0xf6d1e7c3, 0x4848e71b, 0x35ce8218, 0x866eaf6d,
    0x06dd7926, 0x3d86adbc, 0xf14dce25, 0xc73906c9, 0x12460656, 0x3796dad3, 0xe89ea68f, 0xd26793c2,
    0x23005bd9, 0x1064a315, 0xd87a3298, 0xf43ca15c, 0x2b089b69, 0x022c02d8, 0xd06caa1f, 0xf46cad18,
    0x070810b0, 0x18f2d342, 0x3fa9ef55, 0x3ebea5dc, 0x84626376, 0x958f1c4d, 0xb54fcb80, 0xb84dc829,
    0x470fa1fe, 0x5d9324a8, 0x702cac04, 0x64505b17, 0xdeae3ae2, 0xc6eeeedd, 0xfc530776, 0xe8f154e5,
    0x33bee3b2, 0x59515b74, 0xc8cca6f9, 0xadd78c8f, 0x0d178b38, 0x766aec3d, 0xe87a1c51, 0x9ef11c0d,
    0x9e84b6f5, 0xf8c31e95, 0x65779d4c, 0x1cc95ca2, 0xa36cc61d, 0xd8725c1e, 0x5ad258fb, 0x3c375e9f,
    0x04cea398, 0x86675360, 0xefb1513a, 0x632ea6ec, 0x14959373, 0x8732ac5b, 0xee31736e, 0x71a2be81,
    0xe12eca01, 0x7a766c2d, 0x1ab87e5d, 0x9fdb2461, 0xef681d41, 0x69f5991d, 0x1977dcdf, 0x83d3517a,
    0x2f642f64, 0x943b5329, 0x07f418e7, 0xa384784f, 0xfefbf4c2, 0x4b2f2455, 0xd02354cf, 0x78da6d54,
    0x27b9ad0b, 0x8cd9d190, 0x10c3409b, 0xb481dbdb, 0xf1b161be, 0x58915c5f, 0xdcd17cdd, 0x78d1530e,
    0x18e9ba0a, 0x579621f8, 0xb08d05ec, 0xf0b35e46, 0xbb4bc9ec, 0xfa6bf6d5, 0x1a6a2918, 0x46a56293,
    0x796a5b67, 0x33b79e31, 0xdee4579d, 0x8b3cb08d, 0xc08f9958, 0x80860547, 0x6332a4cd, 0x2e90ae7e,
    0x3c735928, 0xc73ca9ef, 0x3ea05561, 0xcad32615, 0x62323980, 0x99460687, 0x673faec9, 0x81d9a697,
    0x38e9456f, 0xc7aee50e, 0x2b9b66d5, 0xcba4a719, 0x7c6d34a6, 0x879aa685, 0x65b7e261, 0x9396a505,
    0x0a2b4122, 0x4943a9d8, 0x11d9fa81, 0x5d6b5d76, 0x3bb468e9, 0x689a56c3, 0x215491f6, 0x6f0e543b,
    0xae4f7098, 0xe452deb6, 0xa57c8cc6, 0xf0ff8ffb, 0x8141e7fb, 0xdf916287, 0x86163764, 0xd5f6abe1,
    0x31adddfe, 0x2a16a9b0, 0x20d4aa7d, 0x34c8d2d5, 0xe1d6177a, 0xe44fdeef, 0xff26e657, 0xe7b697ce,
    0xf0d01e91, 0xe3b42209, 0xef23b200, 0xe3a46060, 0x3eb8ca05, 0x3775b6c4, 0x23b48e47, 0x2734a894,
    0x2baf9b33, 0xd2d42881, 0x73cf2492, 0x92f1df7f, 0xc80d4c91, 0x3f29d7be, 0x99280067, 0x74e367aa,
    0xed285ad9, 0x11f51fcb, 0xbca2f6e7, 0x4a7e95f4, 0x16c93071, 0xe8c024be, 0x527429f5, 0xa4d6af86,
    0x1f3158d1, 0x157ea087, 0xc2e27c5e, 0xc191276c, 0xe17030bf, 0xf80427fe, 0x227da776, 0x309fa7ee,
    0xd6ab4c06, 0xd4ece076, 0x09d9c32b, 0x10e6a261, 0x292b9dda, 0x34dca7fd, 0xf4f5e75c, 0xf0d0a4fc,
    0x2c69c85f, 0x4801a8a3, 0x279fdbfd, 0x4f295c4f, 0x78f2e9c0, 0x0fdc57a8, 0x6016bc89, 0x194c5112,
    0x4f097162, 0x3610d74e, 0x523e05be, 0x35bd2a82, 0x0707e286, 0x61d3e37e, 0x1550965c, 0x6fb4aa09,
    0x07eb7443, 0xfc54a8da, 0x69928340, 0x8f8a53ac, 0x72941a11, 0x8709df96, 0x1864ebe8, 0xf2f496a7,
    0x8b9617bc, 0x60f6af73, 0xf8653ffc, 0x1ce6e518, 0xfbfecf2d, 0x123717bc, 0x90f6a77a, 0x7476a97d,
};
const unsigned int S6[256] = {
    0x4301e0aa, 0x934959bd, 0x08a01c00, 0x55804207, 0x8d3d33d7, 0xdd6e22b0, 0xc1361255, 0x156ebfea,
    0x07add6f6, 0xd0ceabd1, 0x4a49a184, 0x93ca9f6b, 0x4598280b, 0x9f02c8c4, 0x02c707a1, 0xdfdeff6e,
    0xc8c70ddf, 0x993a8ed4, 0x58f14a38, 0x87757d83, 0x48e24911, 0x13cdc99a, 0xd75bd08e, 0x0b6ebf7d,
    0xf5421b0d, 0xac26f7fe, 0x6a7ac372, 0xbeef3fe9, 0x71beed43, 0xafea37a8, 0xec186eb4, 0xb6deffff,
    0x47822eaa, 0x31310013, 0x21976592, 0xdf3bc04b, 0xe3d39772, 0x1811450b, 0x8440fd32, 0xfefeffe3,
    0x7bcd8915, 0x8c05aa0c, 0x142e1875, 0xe87114d4, 0x509514bd, 0xa7cefefc, 0x33e12155, 0xc64ebf64,
    0x4e7cb3ef, 0x2b4934fa, 0xee0dbfea, 0x0036e03f, 0xbe0c8274, 0xdc815251, 0x17deac59, 0xf73eff74,
    0xd4da34de, 0x3f2615a3, 0x7416f6c3, 0x176caba6, 0x2373be35, 0x42d5fde0, 0x870ddbf0, 0x674ebff5,
    0xd09f1a57, 0xd0d1f563, 0xeb3170f8, 0x6318aefc, 0x4babcf28, 0xce7e1c5c, 0x722afc8f, 0x76f68313,
    0x60397e0e, 0x635fd70a, 0x5cd4dd79, 0x545233a5, 0x7201c8d9, 0x7d96b60d, 0x415f6746, 0x4c46c392,
    0x5b58e52a, 0xcaa2600a, 0xfa6cfef8, 0xe4e4d148, 0xae797fce, 0x30d12f76, 0x04c2e474, 0x1c768384,
    0x76d667ed, 0x6fb6cb05, 0xdce2b387, 0x4977c317, 0x83a211a1, 0x1cfa8341, 0x2f851043, 0x3546c303,
    0xd4101457, 0x42a13cfd, 0xa20b414a, 0xbdab3cb0, 0x65c4b98d, 0x7f81fbf7, 0x175c49e8, 0x8d66c31a,
    0x5c55e1ed, 0x4f9c46e7, 0x22be2ca8, 0x3be1a81a, 0x678d266f, 0x71da0025, 0x10791bb2, 0x05d68398,
    0xddef9b1a, 0x38d94a14, 0x7c9d430a, 0x17af5cf4, 0x481666ab, 0xab1d34ad, 0xe447c2a3, 0x8026c38d,
    0x3742883e, 0xdcbeb968, 0x9283ce16, 0xf4fc4758, 0xa1ee90d7, 0xc545c919, 0x0490ff07, 0xe4d68309,
    0xc588a876, 0xc7d42384, 0xd60de7da, 0x5e2d3958, 0xe6b4788e, 0xe303cbfc, 0xff7f6a6a, 0x79e354b0,
    0x35748d28, 0xbe03402a, 0xa9f04a1c, 0xa977e506, 0x170553f0, 0x10cb00ea, 0x843afdec, 0x01531436,
    0x465e57c3, 0x3dc7f6ed, 0x8d382192, 0xf9a8072c, 0xf32fa0e8, 0x8fc4b096, 0x3b961b11, 0x41235427,
    0x33cbf143, 0x48bb3ca5, 0x739729aa, 0x866254b4, 0x86a78788, 0x71f75da6, 0xc0d1a6a9, 0xb05314a7,
    0x491fc7b6, 0xb5aceb5a, 0x772e9e28, 0x0286ab54, 0x18ca6fab, 0xe2ac2d17, 0x2859974d, 0x527314b9,
    0x1110720b, 0x62c8d0c7, 0xaf93f2cd, 0x54dc7ef9, 0x4288ddc6, 0xbcd7b7c2, 0xf75cc818, 0x88c3543c,
    0xc8f14833, 0x6fb4ddf3, 0x13d0d460, 0xb8fb8ad0, 0x0551d80d, 0xa458aa4d, 0xd94375c6, 0x7d73142e,
    0x6a577e50, 0xcbbb4f88, 0x35ff1d7b, 0x19f1d0bb, 0xa4ea667e, 0x881816be, 0xf98400ad, 0x51c354ad,
    0xd9e9ad73, 0xdbb370a2, 0x8a6374da, 0x074a2a5b, 0xefdd7b89, 0xefec0ae8, 0xb39c7b48, 0x358497b1,
    0x9d1fda28, 0x126dc309, 0x4092c919, 0x4110b630, 0xaf634cda, 0xada081db, 0x785d62f3, 0xfd34d732,
    0x5a3e40ce, 0x71a0e7cb, 0xd05a6aaa, 0xf5c6541f, 0xba4b69cf, 0x9327a982, 0x37f0d013, 0x19c49726,
    0x0fa0725b, 0xa4d4ffa6, 0x0af0a6a7, 0x2e0557b2, 0xeb448492, 0xcd1816b7, 0xecb327a6, 0x4c34d7a3,
    0x557202b3, 0xc9c3284c, 0x2b4d4508, 0x3fe9a857, 0x1122beac, 0x8ac36c13, 0x64badc6f, 0x7e14d7b8,
    0x9977e50b, 0x8eaec3d4, 0x66fc39e8, 0xf8b33dcf, 0xda6f10ec, 0x453cb6e3, 0x2b3b0d07, 0x34a49738,
    0xd49d9f3e, 0x33db5ce5, 0x1ebfd778, 0xf09dc9e3, 0x1cb4c32a, 0xfc3b3349, 0xd525e4c4, 0x3594d72f,
    0x56303d48, 0x37dc1cbb, 0x1c95da56, 0xf59ec3bd, 0x9988b764, 0x7077ddbf, 0xd5e6dba2, 0xbda497a9,
};
const unsigned int S7[256] = {
    0x813c06d4, 0x67033b80, 0x88a17185, 0x7d7ba354, 0xace95364, 0x5aa2776a, 0xa4139684, 0x57e084fb,
    0x15408c02, 0xfa6ec746, 0x1907265c, 0xed2fc499, 0x2ca939fb, 0xd53d3805, 0x3b31ffd0, 0xcffe8e5b,
    0x3267bfc2, 0xae1182e9, 0x417891eb, 0xca159f43, 0x6ae64885, 0xe5bfdd34, 0x1341a399, 0x9d5edc5f,
    0x3cbe068c, 0xba7a97df, 0x5ee36a2a, 0xc7df8efe, 0x7c02fdf2, 0xef2797db, 0x0e5f8aa5, 0x94df4cff,
    0x9f97093b, 0xc080ec10, 0xf05c3a86, 0xb3237184, 0xb8512108, 0xffd49029, 0xd64f2f23, 0x9bffe9df,
    0xdd7e41ad, 0x81a568ba, 0xb3618fff, 0xfb314ec5, 0xe37cee5b, 0xa1fbc0a6, 0x960ec35b, 0xd65fdc7f,
    0x3ecb36db, 0x4e29aa7b, 0xffb9a411, 0x97cd4a9e, 0xe9a64412, 0x828d3d78, 0x22de9cca, 0x473e4e7b,
    0x3978b2d5, 0x59f53821, 0xed464270, 0x9dbefcaf, 0xfbd0aba9, 0x865a9777, 0x3f5ccfda, 0x44fe1edb,
    0x17cfb151, 0x77f08429, 0x2ed64a2c, 0x4f585cfd, 0x569aece9, 0x39908cc7, 0x7ef5a109, 0x1587f376,
    0x86a3778f, 0xedddb0c7, 0xbf3095dd, 0xd94d331c, 0xdb4e4672, 0xa3cf4f88, 0xe946885d, 0x990df1d6,
    0xb7d18843, 0xa263b560, 0x910be66e, 0x98e6e0e6, 0x2495f708, 0x34dc2ab1, 0x00b2d438, 0x096d23d2,
    0x4b997905, 0x558cac5a, 0x7d145da7, 0x73ecf173, 0xde31067f, 0xd915a85e, 0xf0acf520, 0xe2ac3372,
    0x02b47abe, 0xda7213bd, 0x666b4d27, 0xa500ce2d, 0xb2325e85, 0x7ce76380, 0xc92918a6, 0x1998de52,
    0x214d3e20, 0xf4171f3f, 0x41163076, 0x8353b940, 0x808b11d2, 0x5f08ff2f, 0xe5f9f4de, 0x28aca3f2,
    0xb0adc55a, 0xc85addf6, 0xdf8a9f9c, 0xa13e753b, 0x57c53b9f, 0x33efc2f9, 0x34adeb63, 0x530df1f6,
    0xc18f495c, 0xb40203a0, 0xbaf179f5, 0xc58d8322, 0x2df3d024, 0x5869e0f6, 0x402ff057, 0x3a8d6156,
    0x8ac190b3, 0x2ad4aca3, 0x335a6736, 0x92e45475, 0x8316c491, 0x241d83dd, 0x2be081b1, 0x8831d04e,
    0x3b9f5bb5, 0x90f1b0f5, 0x82b4b3ff, 0x24d8332c, 0x26526c4a, 0x9eea4d32, 0x94c28ae5, 0x2409d9ee,
    0x2af4a963, 0x77c6b548, 0xac8fe4dc, 0xe5caca77, 0x3111dfb1, 0x69400a03, 0xbdbef538, 0xf4e90bea,
    0x760d503d, 0x20a980ea, 0xe0105fcd, 0xae6ad95a, 0x63972846, 0x2498806c, 0xe588fcc0, 0xbf281b4a,
    0x97087e4c, 0x8f771b35, 0x5be76c24, 0x58bee6a5, 0x07ae55fc, 0x016b6618, 0xdcbc3896, 0xc42efd6a,
    0x34cb170a, 0x29123f0f, 0xfc923a4d, 0xf6c49970, 0xbd8f38eb, 0xaa24f717, 0x78fdd6ee, 0x7da88bca,
    0x253ac16a, 0x15defddc, 0x820e9137, 0xbc107faa, 0x42513027, 0x6e72e8c9, 0xe921caeb, 0xce89d9ce,
    0xb4a16574, 0x810e0f12, 0x07f55786, 0x30098b0b, 0xd04dfd1c, 0xededc246, 0x758bd93f, 0x4f09496e,
    0x03cdd8c9, 0xa5d8ecf5, 0xcad2a360, 0x7f385423, 0x669a84e3, 0xd8d0878f, 0xaef949c3, 0x15a9583c,
    0x77835fc7, 0xd8bd388b, 0xbb7cff81, 0x0f453b56, 0x0e4aec3c, 0xb7e7c540, 0xd94a0297, 0x6d05599c,
    0xb0bd611d, 0x644b7d3e, 0xa3036ca6, 0x68c64a2d, 0x409d9fc3, 0x87dc0279, 0x51b27d66, 0x9f250b98,
    0x7ed5d04b, 0xb0a04490, 0x7c1897bf, 0xa5a65928, 0x9e5b2c34, 0x4d554016, 0x84847cba, 0x56a49b38,
    0x15d4f236, 0xaa7a1b67, 0x922fe47a, 0x3162a6f3, 0xd232d58e, 0x7da76a4e, 0x5c25f0ec, 0xf9b63518,
    0x77079778, 0xc35fb775, 0xf11a7a3b, 0x5159910a, 0xa187389d, 0x0b283761, 0x34f51e94, 0x9ca40bb8,
    0xb4a3cd14, 0x2c5275ae, 0x7dc25545, 0xf51cbff0, 0x03cdb055, 0x80efe8b7, 0xc0ad42bd, 0x454599bc,
    0x53a96102, 0xd306cb6c, 0x8fbd93fc, 0x17c50b79, 0xf991796e, 0x6c214a38, 0x3507194d, 0xae85c91c,
};
const unsigned int S8[256] = {
    0x03755908, 0x8130788b, 0x60b34458, 0xf5a713fb, 0x1b3e6039, 0x84ce8770, 0x62da564e, 0xfad6beb4,
    0x10e90337, 0x8e7bb301, 0x687c5e1a, 0xe4c286dd, 0x0470b043, 0x9d7f8fed, 0x672370b0, 0xfcad5e7c,
    0x8a7833e0, 0x19203447, 0x1600c2a6, 0x9ffb87ac, 0xadf01f95, 0x3cc7c2ec, 0x2e36e31e, 0xb50f0559,
    0xf527ecc1, 0x62dc821e, 0x7ccafc4b, 0xf4efcee8, 0xcbf3b9bf, 0x444f44ec, 0x5c441201, 0xdc8bcabd,
    0x0f01e193, 0x0e403103, 0x933c20ef, 0x976db906, 0x5aaf1212, 0x5ad1188c, 0xd9d9f5b3, 0xcc1acfc7,
    0x1fe6961f, 0x0b562563, 0x85e12831, 0x913ccce5, 0x5748c7ed, 0x58efe7cd, 0xd3e0e9e7, 0xcc87e7fc,
    0x8dbab47f, 0xcbd07112, 0x6a4796f4, 0x24cf2e6d, 0xa427ad45, 0xfca8ae32, 0x590d8ff9, 0x19cd88e9,
    0x319e46ed, 0x7a7118a1, 0xde9fba85, 0x98ef87ec, 0x108d0eea, 0x5fafdfee, 0xe4bf444c, 0xb6af8ffe,
    0xbb0c22ed, 0x1d4c4774, 0x5ac87aad, 0xefdb2d0c, 0x8f401cc4, 0x24b4b09f, 0x78a42da1, 0xdceac743,
    0x6c9138da, 0xd20381f6, 0x940561ff, 0x20babd2a, 0x4a0acbbc, 0xe703b51a, 0xa71c4a55, 0x1cd1258b,
    0x34054217, 0x015c03b0, 0x0a7afc51, 0x2583f85b, 0x398b2362, 0x04b9fd09, 0x16489fe9, 0x2d3370ae,
    0x215e953c, 0x0aa4b0e9, 0x04b7c0a6, 0x2c93f71f, 0x318dc948, 0x0c337d19, 0x067a2ff6, 0x24f3fd4a,
    0xbb7d9a64, 0xfa3c0afc, 0xb9451c02, 0xed1585f1, 0x22d62be7, 0x60ab6163, 0x23a7c95c, 0x6822fe32,
    0xcd9ba7e0, 0x9f2e1b94, 0xcb9a17cc, 0x9540f512, 0x5735f71a, 0x18939f3a, 0x51df9202, 0x0effd009,
    0x3fc2c59a, 0x1bac42e5, 0xa63faa1b, 0x9eb3539a, 0xfc5bd4ba, 0xded6dfd7, 0x6173b40e, 0x43f5b51c,
    0xebe23502, 0xda092656, 0x74e08670, 0x4097bc1b, 0x24f43515, 0x0dd3a41b, 0xbc8138bb, 0x8cd3f40b,
    0x9cd38f74, 0x7a168aab, 0xff37b654, 0x0aa1e1d3, 0xe80a8279, 0x13e26d24, 0x9dfe103e, 0x69b058bc,
    0x2be77547, 0xd55d5d4d, 0x53da9c66, 0xb76470b5, 0x5f445603, 0xa2d95981, 0x30e706cc, 0xcb8b3810,
    0x117edd8c, 0xa686ce6f, 0x4d2430aa, 0xe0dd7580, 0xfec46dbd, 0x43eb90d0, 0xb1122152, 0x0ac97f71,
    0xc6998ae1, 0x7d7a7c56, 0x837c0e7f, 0x2bc93880, 0x34d7e7b3, 0x9be93280, 0x6330d06d, 0xc3ad3091,
    0x9c2727fb, 0x7d66c767, 0x4c3af29b, 0xa84b4b2e, 0x05b9f47e, 0xe5fd7edc, 0xc6fd8783, 0x3f7ca18f,
    0x6868f83b, 0x9870c76b, 0xbec5ca71, 0x42ba3a89, 0xe05e29c5, 0x0f49b1a1, 0x2424af9b, 0xdba10dd0,
    0x1a3c4a03, 0x7c768f7e, 0x31e14484, 0x5bc9dc41, 0xdb31db45, 0xab84700a, 0xe62979f1, 0x860b7a81,
    0xaea0389d, 0xcdd7eaad, 0x81ab6889, 0xe7e97180, 0x638b588a, 0x08092982, 0x5bcbb624, 0x2989f992,
    0x3b550b6e, 0xf9954aab, 0x3ab3775e, 0xef2220db, 0x838b017b, 0x4c67a534, 0x987f942e, 0x5073deb4,
    0x2860b155, 0xf6da9045, 0x305c5c7c, 0xece3b4bd, 0x8ec1d203, 0x475a9c89, 0x8f27c3d6, 0x5408bc18,
    0xb0fc5384, 0x41050667, 0x2ea1f1a2, 0xc55af588, 0x5540aeb5, 0xa46a50ca, 0xd693a25a, 0x2d0af579,
    0xcd1f0ce3, 0x2afdb15e, 0x44fecd6d, 0xac4afe88, 0x315668bb, 0xcc6af48a, 0xa6f11265, 0x442af899,
    0x37a4a3f3, 0x76e50367, 0x59bc3189, 0x0dcc8826, 0x623f3274, 0x2078f8cc, 0x037c4493, 0x44bb6f85,
    0xc5ea363b, 0x93f70663, 0xaf410a73, 0xf939fc81, 0x9fdce6cd, 0xd0ca36a9, 0xf9e42b81, 0xa626c5da,
    0xb7bbc419, 0xb3f54376, 0x42668794, 0x5e4a5e49, 0x5cb25d45, 0x5605fe10, 0xa1a8bdf9, 0xa3ccb88b,
    0xab23b48d, 0xb2502ba5, 0x542bab83, 0x406eb588, 0x480d9c8a, 0x458aad88, 0xbc0a352c, 0xac0a7d98,
};
#pragma endregion

/* Helper macros */
#ifndef HIWORD
#define HIWORD(x) (((x) >> 16) & 0xFFFF)
#endif

#ifndef BYTE3
#define BYTE3(x) (((x) >> 24) & 0xFF)
#endif

#ifndef BYTE1
#define BYTE1(x) (((x) >> 8) & 0xFF)
#endif

#ifndef BYTE2
#define BYTE2(x) (((x) >> 16) & 0xFF)
#endif

#ifndef BYTE0
#define BYTE0(x) ((x) & 0xFF)
#endif


/* swap bits */
#ifndef SWAPBITS
#define SWAPBITS(x) \
    ((BYTE0(x) << 24) | (BYTE1(x) << 16) | (BYTE2(x) << 8) | BYTE3(x))
#endif

/* rotate shift */
#ifndef rotl32
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#endif

int CAST3EncryptOneBlock(const CAST3_CTX* context, const BYTE* inData, BYTE* outData)
{
    UINT32 tempLeft, tempRight;
    UINT32 intermediate[24] = { 0 };

    /* Swap bitness */
    CAST3_BLOCK* inBlock = (CAST3_BLOCK*)inData, * outBlock = (CAST3_BLOCK*)outData;

    tempLeft = SWAPBITS(inBlock->as32[0]);
    tempRight = SWAPBITS(inBlock->as32[1]);

    intermediate[0] = rotl32(context->schedule[0] + tempRight, context->schedule[1]);
    intermediate[1] = (S4[BYTE2(intermediate[0])] + (S2[BYTE0(intermediate[0])] ^ S1[BYTE1(intermediate[0])]) - S3[BYTE3(intermediate[0])]) ^ tempLeft;
    intermediate[2] = rotl32(intermediate[1] ^ context->schedule[2], context->schedule[3]);
    intermediate[3] = S4[BYTE2(intermediate[2])] ^ (S3[BYTE3(intermediate[2])] + S1[BYTE1(intermediate[2])] - S2[BYTE0(intermediate[2])]) ^ tempRight;
    intermediate[4] = rotl32(context->schedule[4] - intermediate[3], context->schedule[5]);
    intermediate[5] = ((S3[BYTE3(intermediate[4])] ^ (S2[BYTE0(intermediate[4])] + S1[BYTE1(intermediate[4])])) - S4[BYTE2(intermediate[4])]) ^ intermediate[1];
    intermediate[6] = rotl32(context->schedule[6] + intermediate[5], context->schedule[7]);
    intermediate[7] = (S4[BYTE2(intermediate[6])] + (S2[BYTE0(intermediate[6])] ^ S1[BYTE1(intermediate[6])]) - S3[BYTE3(intermediate[6])]) ^ intermediate[3];
    intermediate[8] = rotl32(intermediate[7] ^ context->schedule[8], context->schedule[9]);
    intermediate[9] = S4[BYTE2(intermediate[8])] ^ (S3[BYTE3(intermediate[8])] + S1[BYTE1(intermediate[8])] - S2[BYTE0(intermediate[8])]) ^ intermediate[5];
    intermediate[10] = rotl32(context->schedule[10] - intermediate[9], context->schedule[11]);
    intermediate[11] = ((S3[BYTE3(intermediate[10])] ^ (S2[BYTE0(intermediate[10])] + S1[BYTE1(intermediate[10])])) - S4[BYTE2(intermediate[10])]) ^ intermediate[7];
    intermediate[12] = rotl32(context->schedule[12] + intermediate[11], context->schedule[13]);
    intermediate[13] = (S4[BYTE2(intermediate[12])] + (S2[BYTE0(intermediate[12])] ^ S1[BYTE1(intermediate[12])]) - S3[BYTE3(intermediate[12])]) ^ intermediate[9];
    intermediate[14] = rotl32(intermediate[13] ^ context->schedule[14], context->schedule[15]);
    intermediate[15] = S4[BYTE2(intermediate[14])] ^ (S3[BYTE3(intermediate[14])] + S1[BYTE1(intermediate[14])] - S2[BYTE0(intermediate[14])]) ^ intermediate[11];
    intermediate[16] = rotl32(context->schedule[16] - intermediate[15], context->schedule[17]);
    intermediate[17] = ((S3[BYTE3(intermediate[16])] ^ (S2[BYTE0(intermediate[16])] + S1[BYTE1(intermediate[16])])) - S4[BYTE2(intermediate[16])]) ^ intermediate[13];
    intermediate[18] = rotl32(context->schedule[18] + intermediate[17], context->schedule[19]);
    intermediate[19] = (S4[BYTE2(intermediate[18])] + (S2[BYTE0(intermediate[18])] ^ S1[BYTE1(intermediate[18])]) - S3[BYTE3(intermediate[18])]) ^ intermediate[15];
    intermediate[20] = rotl32(intermediate[19] ^ context->schedule[20], context->schedule[21]);
    intermediate[21] = S4[BYTE2(intermediate[20])] ^ (S3[BYTE3(intermediate[20])] + S1[BYTE1(intermediate[20])] - S2[BYTE0(intermediate[20])]) ^ intermediate[17];
    intermediate[22] = rotl32(context->schedule[22] - intermediate[21], context->schedule[23]);
    intermediate[23] = ((S3[BYTE3(intermediate[22])] ^ (S2[BYTE0(intermediate[22])] + S1[BYTE1(intermediate[22])])) - S4[BYTE2(intermediate[22])]) ^ intermediate[19];

    /* Swap final bits */
    outBlock->as32[0] = SWAPBITS(intermediate[23]);
    outBlock->as32[1] = SWAPBITS(intermediate[21]);

    return C3E_OK;
}

void CAST3DecryptOneBlock(const CAST3_CTX* context, const BYTE* inData, BYTE* outData)
{
    UINT32 tempLeft, tempRight;
    UINT32 intermediate[24] = { 0 };

    /* Swap bits */
    CAST3_BLOCK* inBlock = (CAST3_BLOCK*)inData, * outBlock = (CAST3_BLOCK*)outData;
    tempLeft = SWAPBITS(inBlock->as32[0]);
    tempRight = SWAPBITS(inBlock->as32[1]);

    intermediate[0] = rotl32(context->schedule[22] - tempRight, context->schedule[23]);
    intermediate[1] = ((S3[BYTE3(intermediate[0])] ^ (S2[BYTE0(intermediate[0])] + S1[BYTE1(intermediate[0])])) - S4[BYTE2(intermediate[0])]) ^ tempLeft;
    intermediate[2] = rotl32(intermediate[1] ^ context->schedule[20], context->schedule[21]);
    intermediate[3] = S4[BYTE2(intermediate[2])] ^ (S3[BYTE3(intermediate[2])] + S1[BYTE1(intermediate[2])] - S2[BYTE0(intermediate[2])]) ^ tempRight;
    intermediate[4] = rotl32(context->schedule[18] + intermediate[3], context->schedule[19]);
    intermediate[5] = (S4[BYTE2(intermediate[4])] + (S2[BYTE0(intermediate[4])] ^ S1[BYTE1(intermediate[4])]) - S3[BYTE3(intermediate[4])]) ^ intermediate[1];
    intermediate[6] = rotl32(context->schedule[16] - intermediate[5], context->schedule[17]);
    intermediate[7] = ((S3[BYTE3(intermediate[6])] ^ (S2[BYTE0(intermediate[6])] + S1[BYTE1(intermediate[6])])) - S4[BYTE2(intermediate[6])]) ^ intermediate[3];
    intermediate[8] = rotl32(intermediate[7] ^ context->schedule[14], context->schedule[15]);
    intermediate[9] = S4[BYTE2(intermediate[8])] ^ (S3[BYTE3(intermediate[8])] + S1[BYTE1(intermediate[8])] - S2[BYTE0(intermediate[8])]) ^ intermediate[5];
    intermediate[10] = rotl32(context->schedule[12] + intermediate[9], context->schedule[13]); 
    intermediate[11] = (S4[BYTE2(intermediate[10])] + (S2[BYTE0(intermediate[10])] ^ S1[BYTE1(intermediate[10])]) - S3[BYTE3(intermediate[10])]) ^ intermediate[7];
    intermediate[12] = rotl32(context->schedule[10] - intermediate[11], context->schedule[11]);
    intermediate[13] = ((S3[BYTE3(intermediate[12])] ^ (S2[BYTE0(intermediate[12])] + S1[BYTE1(intermediate[12])])) - S4[BYTE2(intermediate[12])]) ^ intermediate[9];
    intermediate[14] = rotl32(intermediate[13] ^ context->schedule[8], context->schedule[9]);
    intermediate[15] = S4[BYTE2(intermediate[14])] ^ (S3[BYTE3(intermediate[14])] + S1[BYTE1(intermediate[14])] - S2[BYTE0(intermediate[14])]) ^ intermediate[11];
    intermediate[16] = rotl32(context->schedule[6] + intermediate[15], context->schedule[7]);
    intermediate[17] = (S4[BYTE2(intermediate[16])] + (S2[BYTE0(intermediate[16])] ^ S1[BYTE1(intermediate[16])]) - S3[BYTE3(intermediate[16])]) ^ intermediate[13];
    intermediate[18] = rotl32(context->schedule[4] - intermediate[17], context->schedule[5]);
    intermediate[19] = ((S3[BYTE3(intermediate[18])] ^ (S2[BYTE0(intermediate[18])] + S1[BYTE1(intermediate[18])])) - S4[BYTE2(intermediate[18])]) ^ intermediate[15];
    intermediate[20] = rotl32(intermediate[19] ^ context->schedule[2], context->schedule[3]);
    intermediate[21] = S4[BYTE2(intermediate[20])] ^ (S3[BYTE3(intermediate[20])] + S1[BYTE1(intermediate[20])] - S2[BYTE0(intermediate[20])]) ^ intermediate[17];
    intermediate[22] = rotl32(intermediate[21] + context->schedule[0], context->schedule[1]);
    intermediate[23] = intermediate[19] ^ (S4[BYTE2(intermediate[22])] + (S2[BYTE0(intermediate[22])] ^ S1[BYTE1(intermediate[22])]) - S3[BYTE3(intermediate[22])]);

    /* Swap final bits */
    outBlock->as32[0] = SWAPBITS(intermediate[23]);
    outBlock->as32[1] = SWAPBITS(intermediate[21]);
}

int CAST3UpdateEncryptCBC(CAST3_CTX* context, const BYTE* inData, BYTE* outData, unsigned int* len)
{
    unsigned int bytesProcessed = 0;
    unsigned int fullBlocks;
    CAST3_BLOCK tempBlock;
    BYTE* outputPtr = outData;

    /* Process data in inBuffer */
    if (*len > 0) {
        while (context->inBufferCount < CAST3_BLK_SIZE && *len > 0) {
            context->inBuffer.asBYTE[context->inBufferCount++] = *inData++;
            (*len)--;
        }
    }

    /* Process full block if inBuffer is full */
    if (context->inBufferCount >= CAST3_BLK_SIZE) {
        fullBlocks = (*len) / CAST3_BLK_SIZE;

        /* Process first block */
        for (int i = 0; i < CAST3_BLK_SIZE; i++) {
            tempBlock.asBYTE[i] = context->inBuffer.asBYTE[i] ^ context->cbcBuffer.asBYTE[i];
        }

        CAST3EncryptOneBlock(context, tempBlock.asBYTE, outputPtr);
        memcpy(&context->cbcBuffer, outputPtr, CAST3_BLK_SIZE);

        outputPtr += CAST3_BLK_SIZE;
        bytesProcessed += CAST3_BLK_SIZE;

        /* Process remaining full blocks */
        for (unsigned int block = 0; block < fullBlocks; block++) {
            for (int i = 0; i < CAST3_BLK_SIZE; i++) {
                tempBlock.asBYTE[i] = inData[i] ^ context->cbcBuffer.asBYTE[i];
            }

            CAST3EncryptOneBlock(context, tempBlock.asBYTE, outputPtr);
            memcpy(&context->cbcBuffer, outputPtr, CAST3_BLK_SIZE);

            inData += CAST3_BLK_SIZE;
            outputPtr += CAST3_BLK_SIZE;
            bytesProcessed += CAST3_BLK_SIZE;
        }

        /* Save incomplete last block to inBuffer */
        context->inBufferCount = (*len) % CAST3_BLK_SIZE;
        memcpy(context->inBuffer.asBYTE, inData, context->inBufferCount);
        *len = bytesProcessed;
    }

    return C3E_OK;
}

void CAST3UpdateDecryptCBC(CAST3_CTX* context, const BYTE* inData, BYTE* outData, unsigned int* len)
{
    unsigned int bytesProcessed = 0;
    unsigned int fullBlocks;
    CAST3_BLOCK tempBlock;
    BYTE* outputPtr = outData;
    CAST3_BLOCK prevCipherBlock;

    /* Process data in inBuffer */
    if (*len > 0) {
        while (context->inBufferCount < CAST3_BLK_SIZE && *len > 0) {
            context->inBuffer.asBYTE[context->inBufferCount++] = *inData++;
            (*len)--;
        }
    }

    /* Process full block if inBuffer is full */
    if (context->inBufferCount >= CAST3_BLK_SIZE) {
        /* If lastBlock is valid, output it */
        if (context->lastBlockValid) {
            *(CAST3_BLOCK*)outputPtr = context->lastDecBlock;
            outputPtr += CAST3_BLK_SIZE;
            bytesProcessed += CAST3_BLK_SIZE;
            context->lastBlockValid = FALSE;
        }

        fullBlocks = (*len) / CAST3_BLK_SIZE;
        memcpy(&prevCipherBlock, &context->inBuffer, CAST3_BLK_SIZE);

        /* Process first block */
        CAST3DecryptOneBlock(context, context->inBuffer.asBYTE, tempBlock.asBYTE);
        for (int i = 0; i < CAST3_BLK_SIZE; i++) {
            tempBlock.asBYTE[i] ^= context->cbcBuffer.asBYTE[i];
        }

        memcpy(&context->cbcBuffer, &prevCipherBlock, CAST3_BLK_SIZE);
        *(CAST3_BLOCK*)outputPtr = tempBlock;

        outputPtr += CAST3_BLK_SIZE;
        bytesProcessed += CAST3_BLK_SIZE;

        /* Process remaining full blocks */
        for (unsigned int block = 0; block < fullBlocks; block++) {
            CAST3_BLOCK currentCipherBlock;
            memcpy(&currentCipherBlock, inData, CAST3_BLK_SIZE);

            CAST3DecryptOneBlock(context, inData, tempBlock.asBYTE);
            for (int i = 0; i < CAST3_BLK_SIZE; i++) {
                tempBlock.asBYTE[i] ^= context->cbcBuffer.asBYTE[i];
            }

            memcpy(&context->cbcBuffer, &currentCipherBlock, CAST3_BLK_SIZE);
            *(CAST3_BLOCK*)outputPtr = tempBlock;

            inData += CAST3_BLK_SIZE;
            outputPtr += CAST3_BLK_SIZE;
            bytesProcessed += CAST3_BLK_SIZE;
        }

        /* Save last decrypt block */
        memcpy(&context->lastDecBlock, outputPtr - CAST3_BLK_SIZE, CAST3_BLK_SIZE);
        context->lastBlockValid = TRUE;

        /* Save incomplete last block to inBuffer */
        context->inBufferCount = (*len) % CAST3_BLK_SIZE;
        memcpy(context->inBuffer.asBYTE, inData, context->inBufferCount);
        *len = bytesProcessed - CAST3_BLK_SIZE; /* Last block might contain padding */
    }
}

int CAST3UpdateMAC(CAST3_CTX* context, const BYTE* inData, unsigned int len)
{
    unsigned int bytesProcessed = 0;
    unsigned int fullBlocks;
    CAST3_BLOCK tempBlock;

    /* Process data in inBuffer */
    if (len > 0) {
        while (context->inBufferCount < CAST3_BLK_SIZE && len > 0) {
            context->inBuffer.asBYTE[context->inBufferCount++] = *inData++;
            len--;
        }
    }

    /* Process full block if inBuffer is full */
    if (context->inBufferCount >= CAST3_BLK_SIZE) {
        fullBlocks = len / CAST3_BLK_SIZE;

        /* Process first block */
        for (int i = 0; i < CAST3_BLK_SIZE; i++) {
            tempBlock.asBYTE[i] = context->inBuffer.asBYTE[i] ^ context->cbcBuffer.asBYTE[i];
        }

        CAST3EncryptOneBlock(context, tempBlock.asBYTE, context->cbcBuffer.asBYTE);
        bytesProcessed += CAST3_BLK_SIZE;

        /* Process remaining full blocks */
        for (unsigned int block = 0; block < fullBlocks; block++) {
            for (int i = 0; i < CAST3_BLK_SIZE; i++) {
                tempBlock.asBYTE[i] = inData[i] ^ context->cbcBuffer.asBYTE[i];
            }

            CAST3EncryptOneBlock(context, tempBlock.asBYTE, context->cbcBuffer.asBYTE);
            inData += CAST3_BLK_SIZE;
            bytesProcessed += CAST3_BLK_SIZE;
        }

        /* Save incomplete last block to inBuffer */
        context->inBufferCount = len % CAST3_BLK_SIZE;
        memcpy(context->inBuffer.asBYTE, inData, context->inBufferCount);
    }

    return C3E_OK;
}

int CAST3SetKeySchedule(CAST3_CTX* context, const BYTE* key, unsigned int keyNumBits)
{
	// Store the 3 parts of the key as 32-bit integers
    UINT32 k[3] = { 0, 0, 0 };

	// Store temporary values during key schedule computation
    UINT32 t[18];
    unsigned int i;

	// 1. Check key length
    if (CAST3CheckKeyLen(keyNumBits) != C3E_OK) {
        return C3E_BAD_KEYLEN;
    }

	// 2. Load the key bytes into k[0], k[1], k[2]
    unsigned int keyLenBytes = keyNumBits / CAST3_BLK_SIZE;
    for (i = 0; i < keyLenBytes; ++i) {
        k[i / 4] |= ((UINT32)key[i]) << (24 - (i % 4) * CAST3_BLK_SIZE);
    }

    // --------------------------------------------------------------------------
	// Start key schedule computation, generating 24 subkeys (Km0..Km23 and Kr0..Kr23)
    // --------------------------------------------------------------------------

	// -- Round 1: Calculate t[0], t[1], t[2], and generate Km0..Km3 --

    // Calculate t[0..2]
    t[0] = k[0] ^ S5[BYTE2(k[1])] ^ S6[BYTE0(k[1])] ^ S7[BYTE3(k[1])] ^ S8[BYTE1(k[1])] ^ S7[BYTE3(k[2])];
    t[1] = k[1] ^ S5[BYTE3(t[0])] ^ S6[BYTE1(t[0])] ^ S7[BYTE2(t[0])] ^ S8[BYTE0(t[0])] ^ S8[BYTE2(k[2])];
    t[2] = t[1] ^ S5[BYTE3(k[2])] ^ S6[BYTE2(k[2])] ^ S7[BYTE3(k[2])] ^ S8[BYTE2(k[2])];

	// Generate Km0, Km1, Km2, Km3 (schedule[0], [2], [4], [6])
    context->schedule[0] = S5[BYTE3(t[2])] ^ S6[BYTE2(t[0])] ^ S7[BYTE0(t[1])] ^ S8[BYTE1(t[1])] ^ S5[BYTE3(t[0])];
    context->schedule[2] = S5[BYTE1(t[0])] ^ S6[BYTE0(t[0])] ^ S7[BYTE2(t[1])] ^ S8[BYTE3(t[1])] ^ S6[BYTE2(t[2])];
    context->schedule[4] = S5[BYTE3(t[1])] ^ S6[BYTE2(t[1])] ^ S7[BYTE0(t[0])] ^ S8[BYTE1(t[0])] ^ S7[BYTE1(t[2])];
    context->schedule[6] = S5[BYTE1(t[1])] ^ S6[BYTE0(t[1])] ^ S7[BYTE2(t[0])] ^ S8[BYTE3(t[0])] ^ S8[BYTE0(t[2])];

	// -- Round 2: Calculate t[3], t[4], t[5], and generate Km4..Km7 --

    // Calculate t[3..5]
    t[3] = t[0] ^ S5[BYTE3(t[1])] ^ S6[BYTE1(t[1])] ^ S7[BYTE2(t[1])] ^ S8[BYTE0(t[1])] ^ S7[BYTE3(t[2])];
    t[4] = t[1] ^ S5[BYTE2(t[3])] ^ S6[BYTE0(t[3])] ^ S7[BYTE3(t[3])] ^ S8[BYTE1(t[3])] ^ S8[BYTE2(t[2])];
    t[5] = t[4] ^ S5[BYTE3(t[2])] ^ S6[BYTE2(t[2])] ^ S7[BYTE1(t[2])] ^ S8[BYTE0(t[2])];

    // Generate Km4, Km5, Km6, Km7 (schedule[8], [10], [12], [14])
    context->schedule[8] = S5[BYTE3(t[5])] ^ S6[BYTE1(t[3])] ^ S7[BYTE3(t[4])] ^ S8[BYTE2(t[4])] ^ S5[BYTE0(t[3])];
    context->schedule[10] = S5[BYTE2(t[3])] ^ S6[BYTE3(t[3])] ^ S7[BYTE1(t[4])] ^ S8[BYTE0(t[4])] ^ S6[BYTE2(t[5])];
    context->schedule[12] = S5[BYTE0(t[4])] ^ S6[BYTE1(t[4])] ^ S7[BYTE3(t[3])] ^ S8[BYTE2(t[3])] ^ S7[BYTE1(t[5])];
    context->schedule[14] = S5[BYTE2(t[4])] ^ S6[BYTE3(t[4])] ^ S7[BYTE1(t[3])] ^ S8[BYTE0(t[3])] ^ S8[BYTE0(t[5])];

	// -- Round 3: Calculate t[6], t[7], t[8], and generate Km8..Km11 --

    // Calculate t[6..8]
    t[6] = t[3] ^ S5[BYTE3(t[4])] ^ S6[BYTE1(t[4])] ^ S7[BYTE2(t[4])] ^ S8[BYTE0(t[4])] ^ S7[BYTE3(t[5])];
    t[7] = t[4] ^ S5[BYTE2(t[6])] ^ S6[BYTE0(t[6])] ^ S7[BYTE3(t[6])] ^ S8[BYTE1(t[6])] ^ S8[BYTE2(t[5])];
    t[8] = t[7] ^ S5[BYTE3(t[5])] ^ S6[BYTE2(t[5])] ^ S7[BYTE1(t[5])] ^ S8[BYTE0(t[5])];

    // Generate Km8, Km9, Km10, Km11 (schedule[16], [18], [20], [22])
    context->schedule[16] = S5[BYTE3(t[8])] ^ S6[BYTE1(t[6])] ^ S7[BYTE3(t[7])] ^ S8[BYTE2(t[7])] ^ S5[BYTE0(t[6])];
    context->schedule[18] = S5[BYTE2(t[6])] ^ S6[BYTE3(t[6])] ^ S7[BYTE1(t[7])] ^ S8[BYTE0(t[7])] ^ S6[BYTE2(t[8])];
    context->schedule[20] = S5[BYTE0(t[7])] ^ S6[BYTE1(t[7])] ^ S7[BYTE3(t[6])] ^ S8[BYTE2(t[6])] ^ S7[BYTE1(t[8])];
    context->schedule[22] = S5[BYTE2(t[7])] ^ S6[BYTE3(t[7])] ^ S7[BYTE1(t[6])] ^ S8[BYTE0(t[6])] ^ S8[BYTE0(t[8])];

	// -- Round 4: Calculate t[9], t[10], t[11], and generate Kr0..Kr3 --

    // Calculate t[9..11]
    t[9] = t[6] ^ S5[BYTE2(t[7])] ^ S6[BYTE0(t[7])] ^ S7[BYTE3(t[7])] ^ S8[BYTE1(t[7])] ^ S7[BYTE3(t[8])];
    t[10] = t[7] ^ S5[BYTE3(t[9])] ^ S6[BYTE1(t[9])] ^ S7[BYTE2(t[9])] ^ S8[BYTE0(t[9])] ^ S8[BYTE2(t[8])];
    t[11] = t[10] ^ S5[BYTE3(t[8])] ^ S6[BYTE2(t[8])] ^ S7[BYTE1(t[8])] ^ S8[BYTE0(t[8])];

    // Generate Kr0, Kr1, Kr2, Kr3 (schedule[1], [3], [5], [7])
    context->schedule[1] = S5[BYTE3(t[11])] ^ S6[BYTE2(t[9])] ^ S7[BYTE0(t[10])] ^ S8[BYTE1(t[10])] ^ S5[BYTE3(t[9])];
    context->schedule[3] = S5[BYTE1(t[9])] ^ S6[BYTE0(t[9])] ^ S7[BYTE2(t[10])] ^ S8[BYTE3(t[10])] ^ S6[BYTE2(t[11])];
    context->schedule[5] = S5[BYTE3(t[10])] ^ S6[BYTE2(t[10])] ^ S7[BYTE0(t[9])] ^ S8[BYTE1(t[9])] ^ S7[BYTE1(t[11])];
    context->schedule[7] = S5[BYTE1(t[10])] ^ S6[BYTE0(t[10])] ^ S7[BYTE2(t[9])] ^ S8[BYTE3(t[9])] ^ S8[BYTE0(t[11])];

	// -- Round 5: Calculate t[12], t[13], t[14], and generate Kr4..Kr7 --

    // Calculate t[12..14]
    t[12] = t[9] ^ S5[BYTE3(t[10])] ^ S6[BYTE1(t[10])] ^ S7[BYTE2(t[10])] ^ S8[BYTE0(t[10])] ^ S7[BYTE3(t[11])];
    t[13] = t[10] ^ S5[BYTE2(t[12])] ^ S6[BYTE0(t[12])] ^ S7[BYTE3(t[12])] ^ S8[BYTE1(t[12])] ^ S8[BYTE2(t[11])];
    t[14] = t[13] ^ S5[BYTE3(t[11])] ^ S6[BYTE2(t[11])] ^ S7[BYTE1(t[11])] ^ S8[BYTE0(t[11])];

    // Generate Kr4, Kr5, Kr6, Kr7 (schedule[9], [11], [13], [15])
    context->schedule[9] = S5[BYTE3(t[14])] ^ S6[BYTE1(t[12])] ^ S7[BYTE3(t[13])] ^ S8[BYTE2(t[13])] ^ S5[BYTE0(t[12])];
    context->schedule[11] = S5[BYTE2(t[12])] ^ S6[BYTE3(t[12])] ^ S7[BYTE1(t[13])] ^ S8[BYTE0(t[13])] ^ S6[BYTE2(t[14])];
    context->schedule[13] = S5[BYTE0(t[13])] ^ S6[BYTE1(t[13])] ^ S7[BYTE3(t[12])] ^ S8[BYTE2(t[12])] ^ S7[BYTE1(t[14])];
    context->schedule[15] = S5[BYTE2(t[13])] ^ S6[BYTE3(t[13])] ^ S7[BYTE1(t[12])] ^ S8[BYTE0(t[12])] ^ S8[BYTE0(t[14])];

	// -- Round 6: Calculate t[15], t[16], t[17], and generate Kr8..Kr11 --

	// Calculate t[15..17]
    t[15] = t[12] ^ S5[BYTE3(t[13])] ^ S6[BYTE1(t[13])] ^ S7[BYTE2(t[13])] ^ S8[BYTE0(t[13])] ^ S7[BYTE3(t[14])];
    t[16] = t[13] ^ S5[BYTE2(t[15])] ^ S6[BYTE0(t[15])] ^ S7[BYTE3(t[15])] ^ S8[BYTE1(t[15])] ^ S8[BYTE2(t[14])];
    t[17] = t[16] ^ S5[BYTE3(t[14])] ^ S6[BYTE2(t[14])] ^ S7[BYTE1(t[14])] ^ S8[BYTE0(t[14])];

    // Generate Kr8, Kr9, Kr10, Kr11 (schedule[17], [19], [21], [23])
    context->schedule[17] = S5[BYTE3(t[17])] ^ S6[BYTE1(t[15])] ^ S7[BYTE3(t[16])] ^ S8[BYTE2(t[16])] ^ S5[BYTE0(t[15])];
    context->schedule[19] = S5[BYTE2(t[15])] ^ S6[BYTE3(t[15])] ^ S7[BYTE1(t[16])] ^ S8[BYTE0(t[16])] ^ S6[BYTE2(t[17])];
    context->schedule[21] = S5[BYTE0(t[16])] ^ S6[BYTE1(t[16])] ^ S7[BYTE3(t[15])] ^ S8[BYTE2(t[15])] ^ S7[BYTE1(t[17])];
    context->schedule[23] = S5[BYTE2(t[16])] ^ S6[BYTE3(t[16])] ^ S7[BYTE1(t[15])] ^ S8[BYTE0(t[15])] ^ S8[BYTE0(t[17])];

	// 3. Adjust the rotation amounts for Kr_i
    // (Kr_i = (Kr_i - 16) mod 32)
	// Operate on odd indices of schedule array
    for (i = 1; i < CAST3_NUM_ROUNDS * 2; i += 2) {
        context->schedule[i] = ((BYTE)context->schedule[i] - 16) & 0x1F;
    }

    return C3E_OK;
}

int CAST3StartEncryptCBC(CAST3_CTX* context, const BYTE* iv)
{
    memcpy(&context->cbcBuffer, iv, CAST3_BLK_SIZE);
    context->inBufferCount = 0;
    return C3E_OK;
}

int CAST3EndEncryptCBC(CAST3_CTX* context, BYTE* outData, unsigned int* len)
{
    BYTE paddingValue;
    unsigned int paddingLength;
    unsigned int i;

    paddingLength = CAST3_BLK_SIZE - context->inBufferCount;
    paddingValue = (BYTE)paddingLength;

	/* Apply PKCS#7 padding */
    for (i = context->inBufferCount; i < CAST3_BLK_SIZE; i++) {
        context->inBuffer.asBYTE[i] = paddingValue;
    }

    context->inBufferCount = CAST3_BLK_SIZE;
    *len = 0;
    CAST3UpdateEncryptCBC(context, context->inBuffer.asBYTE, outData, len);

    return C3E_OK;
}

void CAST3StartDecryptCBC(CAST3_CTX* context, const BYTE* iv)
{
    memcpy(&context->cbcBuffer, iv, CAST3_BLK_SIZE);
    context->lastBlockValid = FALSE;
    context->inBufferCount = 0;
}

int CAST3EndDecryptCBC(CAST3_CTX* context, BYTE* outData, unsigned int* len)
{
    unsigned int dataLength = 0;
    BYTE paddingValue;

    if (!context->lastBlockValid) {
        *len = 0;
        return C3E_OK;
    }

    /* Check Paddding */
    paddingValue = context->lastDecBlock.asBYTE[CAST3_BLK_SIZE - 1];
    if (paddingValue == 0 || paddingValue > CAST3_BLK_SIZE) {
        return C3E_DEPAD_FAILURE;
    }

    /* Validate padding */
    for (unsigned int i = CAST3_BLK_SIZE - paddingValue; i < CAST3_BLK_SIZE; i++) {
        if (context->lastDecBlock.asBYTE[i] != paddingValue) {
            return C3E_DEPAD_FAILURE;
        }
    }

	/* Calculate data length without padding and copy to output */
    dataLength = CAST3_BLK_SIZE - paddingValue;
    memcpy(outData, context->lastDecBlock.asBYTE, dataLength);

    context->lastBlockValid = FALSE;
    context->inBufferCount = 0;
    *len = dataLength;

    return C3E_OK;
}

int CAST3StartMAC(CAST3_CTX* context, const BYTE* iv)
{
    memcpy(&context->cbcBuffer, iv, CAST3_BLK_SIZE);
    context->inBufferCount = 0;
    return C3E_OK;
}

int CAST3EndMAC(CAST3_CTX* context)
{
    unsigned int i;

    /* Fill buffer with zero padding */
    if (context->inBufferCount > 0) {
        for (i = context->inBufferCount; i < CAST3_BLK_SIZE; i++) {
            context->inBuffer.asBYTE[i] = 0;
            context->inBufferCount++;
        }

        CAST3UpdateMAC(context, context->inBuffer.asBYTE, 0);
    }

    return C3E_OK;
}

void CAST3Cleanup(CAST3_CTX* context)
{
    memset(context, 0, sizeof(CAST3_CTX));
}

int CAST3CheckKeyLen(unsigned int keyNumBits)
{
    if (keyNumBits == 0 || keyNumBits > CAST3_MAX_KEY_NBITS || (keyNumBits % CAST3_BLK_SIZE) != 0) {
        return C3E_BAD_KEYLEN;
    }
    return C3E_OK;
}

static const BYTE k_key[CAST3_BLK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static const CHAR k_plaintext[25] = "Now is the time for all ";
static const CHAR k_plaintextForMACTest[29] = "7654321 Now is the time for ";
static const BYTE k_iv[CAST3_BLK_SIZE] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
static const BYTE k_correctCiphertextECB[CAST3_BLK_SIZE] = { 0x1D, 0xC6, 0xD3, 0x28, 0xBE, 0xEA, 0x36, 0xCE };
static const BYTE k_correctCiphertextCBC[32] = {
    0xEC, 0x53, 0x06, 0x43, 0x2B, 0x9E, 0xBD, 0x32,
    0xC6, 0x4F, 0xB3, 0x2A, 0x38, 0x68, 0x0E, 0xC6,
    0xEC, 0x2A, 0xA9, 0x0B, 0x1B, 0x57, 0x3A, 0x08,
    0xC3, 0x69, 0xD1, 0x34, 0xFF, 0x72, 0x6B, 0xC7 
};
static const BYTE k_correctMAC[CAST3_BLK_SIZE] = { 0xEC, 0x16, 0xE1, 0x7F, 0x30, 0xC4, 0xD3, 0x0B };
int CAST3SelfTest(void)
{
    CAST3_CTX context = { 0 };
    BYTE outData[32];
    unsigned int len;
    int result;

	/* Test ECB mode encryption/decryption */
    if (CAST3SetKeySchedule(&context, k_key, 64) != C3E_OK) {
        return C3E_SELFTEST_FAILED;
    }

    memset(outData, 0, sizeof(outData));
    if (CAST3EncryptOneBlock(&context, (BYTE*)k_plaintext, outData) != C3E_OK) {
        return C3E_SELFTEST_FAILED;
    }

    if (memcmp(outData, k_correctCiphertextECB, CAST3_BLK_SIZE) != 0) {
        return C3E_SELFTEST_FAILED;
    }

    CAST3DecryptOneBlock(&context, outData, outData);

    if(memcmp(outData, k_plaintext, CAST3_BLK_SIZE) != 0) {
        return C3E_SELFTEST_FAILED;
	}

	/* Test CBC mode encryption */
    CAST3StartEncryptCBC(&context, k_iv);
    len = 24;
    CAST3UpdateEncryptCBC(&context, (BYTE*)k_plaintext, outData, &len);

    if (len != 24) {
        return C3E_SELFTEST_FAILED;
    }

    CAST3EndEncryptCBC(&context, &outData[24], &len);

    if (len != CAST3_BLK_SIZE) {
        return C3E_SELFTEST_FAILED;
    }
    if (memcmp(outData, k_correctCiphertextCBC, 32)) {
        return C3E_SELFTEST_FAILED;
    }
	/* Test CBC mode decryption */
    CAST3StartDecryptCBC(&context, k_iv);
    len = 32;
    CAST3UpdateDecryptCBC(&context, k_correctCiphertextCBC, outData, &len);

    if (len != 24) {
        return C3E_SELFTEST_FAILED;
    }

    result = CAST3EndDecryptCBC(&context, &outData[24], &len);
    if (result != C3E_OK || len != 0) {
        return C3E_SELFTEST_FAILED;
    }

    if (memcmp(outData, k_plaintext, 24) != 0) {
        return C3E_SELFTEST_FAILED;
    }

	/* Test MAC calculation */
    CAST3StartMAC(&context, k_iv);
    CAST3UpdateMAC(&context, (BYTE*)k_plaintextForMACTest, 28);
    CAST3EndMAC(&context);

	/* MAC is in context.cbcBuffer */
    if(memcmp(&context.cbcBuffer, k_correctMAC, CAST3_BLK_SIZE)!=0) {
        return C3E_SELFTEST_FAILED;
	}
    return C3E_OK;
}