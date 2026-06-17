use crate as pallet_did;
use frame_support::traits::ConstU64;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;

#[allow(dead_code)]
type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Did: pallet_did,
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type Block = Block;
    type BlockWeights = ();
    type BlockLength = ();
    type AccountId = u64;
    type RuntimeCall = RuntimeCall;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type BlockHashCount = ConstU64<250>;
    type DbWeight = ();
    type Version = ();
    type PalletInfo = PalletInfo;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type AccountData = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_did::pallet::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_did::default_weights::DefaultWeightInfo<Test>;
    type MaxJwkLength = frame_support::traits::ConstU32<4096>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("test storage should build")
        .into()
}
