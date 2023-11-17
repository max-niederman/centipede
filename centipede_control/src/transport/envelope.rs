use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::message::Message;

/// An envelope containing a message or acknowledgement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Envelope {
    Message { sequence: u64, message: Message },
    Acknowledgement { sequence: u64 },
}

/// An envelope which has been authenticated to be from a particular sender.
#[derive(Debug, Clone)]
pub struct AuthenticatedEnvelope {
    /// The public key of the sender.
    pub sender: VerifyingKey,

    /// The envelope.
    pub envelope: Envelope,
}

impl Envelope {
    pub fn sign(&self, key: &SigningKey) -> Result<SignedEnvelope, Error> {
        let envelope = bincode::serialize(self).expect("failed to serialize envelope");
        let signature = key.sign(&envelope);

        Ok(SignedEnvelope {
            sender: key.verifying_key(),
            signature,
            envelope,
        })
    }
}

/// An envelope serialized and signed for authentication by a peer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedEnvelope {
    /// The public key of the sender.
    sender: VerifyingKey,

    /// The signature of the envelope.
    signature: Signature,

    /// The serialized envelope.
    envelope: Vec<u8>,
}

impl SignedEnvelope {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("failed to serialize signed envelope")
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(bytes).map_err(Error::DeserializeSignedEnvelope)
    }

    pub fn claimed_sender(&self) -> VerifyingKey {
        self.sender
    }

    pub fn verify(&self) -> Result<AuthenticatedEnvelope, Error> {
        let SignedEnvelope {
            sender,
            signature,
            envelope,
        } = self;

        sender
            .verify_strict(envelope, signature)
            .map_err(Error::Verify)?;

        Ok(AuthenticatedEnvelope {
            sender: *sender,
            envelope: bincode::deserialize(envelope).map_err(Error::DeserializeEnvelope)?,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to deserialize envelope")]
    DeserializeEnvelope(#[source] bincode::Error),

    #[error("failed to deserialize signed envelope")]
    DeserializeSignedEnvelope(#[source] bincode::Error),

    #[error("failed to verify signature")]
    Verify(#[source] ed25519_dalek::SignatureError),
}
