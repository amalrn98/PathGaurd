//! Authorization is separate from authentication, and deny-by-default.

mod common;

use common::{handshake, make_hello, new_receiver, reject};
use pathguard::crypto::Identity;
use pathguard::message::RejectCode;
use pathguard::SenderPolicy;

#[test]
fn fresh_receiver_denies_a_validly_signed_stranger() {
    let mut recv = new_receiver().0;
    let stranger = Identity::generate();
    let h = make_hello(&stranger, &recv.public());
    assert_eq!(reject(&recv.handle(&h.bytes)), Some(RejectCode::AuthFailed));
    assert_eq!(recv.session_count(), 0, "no session may be created for an unauthorized sender");
    assert_eq!(recv.stats().rejected_unauthorized, 1);
    assert_eq!(*recv.sender_policy(), SenderPolicy::DenyAll);
}

#[test]
fn explicitly_trusted_identity_can_open_a_session() {
    let mut recv = new_receiver().0;
    let alice = Identity::generate();
    recv.allow_sender(alice.public());
    assert!(handshake(&mut recv, &alice).is_some());
    assert_eq!(recv.session_count(), 1);
}

#[test]
fn untrusted_identity_is_rejected_when_others_are_trusted() {
    let mut recv = new_receiver().0;
    recv.allow_sender(Identity::generate().public());
    let mallory = Identity::generate();
    assert!(handshake(&mut recv, &mallory).is_none());
    assert_eq!(recv.session_count(), 0);
    assert_eq!(recv.stats().rejected_unauthorized, 1);
}

#[test]
fn empty_allow_list_denies_everyone() {
    let mut recv = new_receiver().0;
    recv.set_sender_policy(SenderPolicy::AllowList(Default::default()));
    assert!(handshake(&mut recv, &Identity::generate()).is_none());
}

#[test]
fn unauthorized_and_bad_signature_look_identical_on_the_wire() {
    // No oracle for which identities are trusted.
    let mut recv = new_receiver().0;
    let trusted = Identity::generate();
    recv.allow_sender(trusted.public());
    let stranger = Identity::generate();
    let a = recv.handle(&make_hello(&stranger, &recv.public()).bytes);
    let mut forged = make_hello(&trusted, &recv.public()).bytes;
    let n = forged.len();
    forged[n - 1] ^= 1;
    let b = recv.handle(&forged);
    assert_eq!(reject(&a), reject(&b));
}

#[test]
fn policy_updates_take_effect_and_close_sessions() {
    let mut recv = new_receiver().0;
    let (alice, bob) = (Identity::generate(), Identity::generate());
    recv.allow_sender(alice.public());
    recv.allow_sender(bob.public());
    assert!(handshake(&mut recv, &alice).is_some());
    assert!(handshake(&mut recv, &bob).is_some());
    assert_eq!(recv.session_count(), 2);

    // Revocation (key rotation or compromise) closes only that sender's sessions.
    assert!(recv.revoke_sender(&alice.public()));
    assert_eq!(recv.session_count(), 1);
    assert!(handshake(&mut recv, &alice).is_none());
    assert!(!recv.revoke_sender(&alice.public()), "second revoke reports not listed");

    // Replacing the policy with deny-all closes everything.
    recv.set_sender_policy(SenderPolicy::DenyAll);
    assert_eq!(recv.session_count(), 0);
    assert!(handshake(&mut recv, &bob).is_none());
}

#[test]
fn allow_any_authenticated_is_explicit_and_allow_sender_narrows_it() {
    let mut recv = new_receiver().0;
    recv.allow_any_authenticated_sender();
    let (alice, mallory) = (Identity::generate(), Identity::generate());
    assert!(handshake(&mut recv, &mallory).is_some());
    recv.allow_sender(alice.public());
    assert!(matches!(recv.sender_policy(), SenderPolicy::AllowList(s) if s.len() == 1));
    assert!(handshake(&mut recv, &mallory).is_none());
    assert!(handshake(&mut recv, &alice).is_some());
}
