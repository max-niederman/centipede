use centipede_router::{controller::ControllerHandle, worker::WorkerHandle, Router};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

/// A dummy cipher for testing.
pub fn dummy_cipher() -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&[0; 32].into())
}

/// Get one controller and one worker handle to the router.
pub fn get_single_handles(router: &mut Router) -> (ControllerHandle<'_>, WorkerHandle<'_>) {
    let (mut controller, workers) = router.handles(1);
    let mut worker = workers.into_iter().next().unwrap();

    (controller, worker)
}
