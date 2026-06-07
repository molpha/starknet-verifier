//! Golden fixtures shared by the parity and end-to-end tests.
//!
//! All values are produced by the Molpha EVM stack
//! (`molpha-core-contracts/test/fixtures/fixture.json` and the 8-node compat
//! fixture) and independently reproduced with a from-scratch secp256k1
//! reference implementation.

use verifier::byte_utils::append_u256_be;

// ---- 10-node fixture (fixture.json): registryVersion 10, redundancyBuffer 2 ----
pub const REG_VERSION: u32 = 10;
pub const SIGS_REQUIRED: u32 = 3;
pub const TIMESTAMP: u64 = 1704033771;
pub const SIGNERS_BITMAP: u256 = 906;
pub const COMMITMENT: felt252 = 0xc8ecf2b96a23ef5db880f60b2913d2d5bc656fbd;

pub fn JOB_ID() -> u256 {
    u256 { high: 0x11d70673c54b7e0bfb0359cce40a7be4, low: 0xfea039e102be62271823a2cfe6358679 }
}
pub fn VALUE() -> u256 {
    u256 { high: 0x8a4fb565487814f6a54275bb3adc033b, low: 0x5783fe8c5607800ed4aefb60d98a9f96 }
}
pub fn SIGNATURE() -> u256 {
    u256 { high: 0xde6f84021578465b9dd6af0d6516e8cf, low: 0xac52b4339e2465a6860aa57d64814979 }
}
pub fn MESSAGE() -> u256 {
    u256 { high: 0xa8a66c852c309ebed87200b3b9111c1f, low: 0x6de5342b62b14754632b5576e4d5a95d }
}
pub fn SELECTION_SEED() -> u256 {
    u256 { high: 0xabe5aee95ff630a675962dba8d009e10, low: 0x4fe40a270e174c3441c4f7e495ca81a7 }
}
pub fn AGG_X() -> u256 {
    u256 { high: 0x753cc1f4ad1d6cd025d821a41470448c, low: 0xa26055c48e79c6702ab0f12abb3547b2 }
}
pub fn AGG_Y() -> u256 {
    u256 { high: 0x6b2eeb561dd609624855bfc70ce679fc, low: 0xf6e1d0f32280da95cf0760b84531b1f9 }
}

// ---- 8-node compat fixture: registryVersion 8, redundancyBuffer 2 ----
pub const COMMITMENT8: felt252 = 0x77876a88E5552f1Ea7Bea643ac009611EF8d28df;
pub const SIGNERS_BITMAP8: u256 = 255;
pub fn SIGNATURE8() -> u256 {
    u256 { high: 0x2f23ba52761a50b5247e3f76f695dff8, low: 0xa9723bf7da8305c13102f72abd08d44c }
}
pub fn MESSAGE8() -> u256 {
    u256 { high: 0xb47cb74ada1ca532703e6988e725cb62, low: 0x275b1dfa5e801b7a5e92cc10fb682a4f }
}
pub fn AGG_X8() -> u256 {
    u256 { high: 0xa7ef0abdb47fb86ad2bb1e476be56ec0, low: 0x7c06b81814afc09914660e15157ae093 }
}
pub fn AGG_Y8() -> u256 {
    u256 { high: 0xc9038319489a2cbbf33c76e13cb8de0d, low: 0x38558ec58790426ad97e575f3c1f9532 }
}

/// (prefix, x, secret_key) for each of the 10 fixture nodes, in index order.
pub fn fixture_nodes() -> Array<(u8, u256, u256)> {
    array![
        (
            2,
            u256 { high: 0xa6fe671a4f8fc31d46429f11372ce0c5, low: 0xbeb43299d80bf2fd21729c4f13dc98cd },
            u256 { high: 0xdccd846870a0e6b6dddc9b3e5fa34f76, low: 0x35bb8a86e694d4546a0cefb55db67c8c },
        ),
        (
            3,
            u256 { high: 0x4cebeb7e37d08325cb292a2204353a2b, low: 0x27f1c763a986d8458e09aac3eba4fede },
            u256 { high: 0x3656816bd1dc1f9376cc88b10e9970ab, low: 0xa28832f6bdbee32d0c53ab41524fb78c },
        ),
        (
            3,
            u256 { high: 0x02b050226e073e9da860408d1f660eed, low: 0x276d91302022f34ed506e533ea4acd27 },
            u256 { high: 0x9d1c13a4e73bb89893d335686a33ba1b, low: 0xa21d0860129e0792625a0622051172a8 },
        ),
        (
            2,
            u256 { high: 0xfbb6013550d01c1e8d8fa4f572f1d3bb, low: 0x4705e6802ec4e7f7f0e562fdba9f2a88 },
            u256 { high: 0xf9eec62913301ae5e9c9422b495f7def, low: 0xa231d5e73b3a3cd0f1328aaee07ae159 },
        ),
        (
            3,
            u256 { high: 0x589a4adf595419d956fc49c3e8dcaa00, low: 0x29d639279eb620062fdb2dc03bf792b6 },
            u256 { high: 0x7538a7d2b0fd23bc666123dcb68bf449, low: 0x4b33f4fb9ac4eedfc9db1ea49fa55961 },
        ),
        (
            3,
            u256 { high: 0x2e39b3907b6f7ba5d64d920569be5a6a, low: 0x3276572fc2ed67294bf5f71c4c9cc933 },
            u256 { high: 0x861b9c51f8dad7a8dc9d022e70d5374e, low: 0x5c9c3e85c0f973c925270df07a4d0053 },
        ),
        (
            3,
            u256 { high: 0xf5c861e98731c273cd53df1549e8a734, low: 0x6a66c7bfff8c6a68b28d6bae60ecc2fa },
            u256 { high: 0x4dd815463ef2675b855be15a3b6d36f7, low: 0xe553e8b758822b4246ae0d1bb823e384 },
        ),
        (
            3,
            u256 { high: 0x90772fc403eb35264f1f3941da54068e, low: 0xc8cb40e830d9fd8ef8fe25ff1b4442ca },
            u256 { high: 0x8985f1199466837e14fa00e323c628d2, low: 0x94fb629b9b24233547d5ea5185fdde96 },
        ),
        (
            3,
            u256 { high: 0xf6412e5efb52042b28a9b1de7b220404, low: 0xf5749c121f3404293b086acc2ab0bee8 },
            u256 { high: 0x40d4a2af312128240635b1823ca2498d, low: 0xfd765f909fadd33c934e1d46b06692b5 },
        ),
        (
            2,
            u256 { high: 0xd054680ed556a0f7e8268ca13d7e8cd0, low: 0x305081f2742eeef7c4794d81e746a5a9 },
            u256 { high: 0x0222396eb237cecf683b419cd7d75777, low: 0x74d5117ff982e68606128dd373a1e9da },
        ),
    ]
}

/// Builds a 33-byte compressed pubkey ByteArray from prefix + x.
pub fn compressed(prefix: u8, x: u256) -> ByteArray {
    let mut b: ByteArray = "";
    b.append_byte(prefix);
    append_u256_be(ref b, x);
    b
}
