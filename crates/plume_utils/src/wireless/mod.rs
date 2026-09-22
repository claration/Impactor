mod discovery;
mod pairing;
mod store;

pub use discovery::{
    DiscoveredDevice, MANUAL_PAIRING_SERVICE, REMOTE_PAIRING_SERVICE, ServiceKind, discover,
};
pub use idevice::remote_pairing::RpPairingFile;
pub use pairing::{PairedDevice, pair, verify};
pub use store::{PairingRecord, PairingStore};
