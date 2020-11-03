// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate hacl_star;
extern crate rand;

use criterion::Criterion;

mod ed25519_benches {
    use super::*;
    use ed25519_dalek::ExpandedSecretKey;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::PublicKey;
    use ed25519_dalek::Signature;
    use ed25519_dalek::Signer;
    use rand::prelude::ThreadRng;
    use rand::thread_rng;

    fn sign(c: &mut Criterion) {
        let mut sign_group = c.benchmark_group("Ed25519 signing");

        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        let (hacl_secret, _hacl_public) = hacl_star::ed25519::keypair(&mut csprng);

        sign_group.bench_function("Dalek signing", move |b| b.iter(|| keypair.sign(msg)));
        sign_group.bench_function("Hacl signing", move |b| {
            b.iter(|| hacl_secret.signature(msg))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut verify_group = c.benchmark_group("Ed25519 verification");

        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);

        let (hacl_secret, hacl_public) = hacl_star::ed25519::keypair(&mut csprng);
        let hacl_signature = hacl_secret.signature(msg);

        verify_group.bench_function("Dalek signature verification", move |b| {
            b.iter(|| keypair.verify(msg, &sig))
        });
        verify_group.bench_function("Hacl signature verification", move |b| {
            b.iter(|| hacl_public.clone().verify(msg, &hacl_signature))
        });
    }

    fn key_generation(c: &mut Criterion) {
        let mut keygen_group = c.benchmark_group("Ed25519 keygen");
        let mut csprng: ThreadRng = thread_rng();

        keygen_group.bench_function("Dalek keypair generation", move |b| {
            b.iter(|| Keypair::generate(&mut csprng))
        });
        keygen_group.bench_function("Hacl keypair generation", move |b| {
            b.iter(|| hacl_star::ed25519::keypair(&mut csprng))
        });
    }

    criterion_group! {
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            key_generation,
    }
}

criterion_main!(ed25519_benches::ed25519_benches,);
