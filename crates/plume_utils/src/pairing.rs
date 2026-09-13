#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingFailure {
    Cancelled,
    InvalidPin,
    WrongPin,
    StaleRecord,
    ServiceDisappeared,
    Protocol(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStage {
    Reconnected,
    Paired,
}

#[allow(async_fn_in_trait)]
pub trait PairingBackend {
    async fn verify(&mut self) -> Result<(), PairingFailure>;
    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure>;
}

pub async fn ensure_pairing<B, F, Fut>(
    backend: &mut B,
    has_cached_record: bool,
    has_pairing_service: bool,
    has_reconnect_service: bool,
    pin_provider: F,
) -> Result<PairingStage, PairingFailure>
where
    B: PairingBackend,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = String>,
{
    if has_cached_record && (has_reconnect_service || has_pairing_service) {
        if backend.verify().await.is_ok() {
            return Ok(PairingStage::Reconnected);
        }
        if !has_pairing_service {
            return Err(PairingFailure::StaleRecord);
        }
    }

    if !has_pairing_service {
        return Err(PairingFailure::ServiceDisappeared);
    }

    let pin = pin_provider().await;
    if pin.is_empty() {
        return Err(PairingFailure::Cancelled);
    }
    if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PairingFailure::InvalidPin);
    }

    backend.pair(&pin).await?;
    Ok(PairingStage::Paired)
}
