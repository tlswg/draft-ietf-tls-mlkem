---
title: "ML-KEM Post-Quantum Key Agreement for TLS 1.3"
abbrev: ietf-tls-mlkem
category: info

docname: draft-ietf-tls-mlkem-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - kems
 - tls

area: "Security"
workgroup: "Transport Layer Security"
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "tlswg/draft-ietf-tls-mlkem"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  AVIRAM:
    target: https://mailarchive.ietf.org/arch/msg/tls/F4SVeL2xbGPaPB2GW_GkBbD_a5M/
    title: "[TLS] Combining Secrets in Hybrid Key Exchange in TLS 1.3"
    date: 2021-09-01
    author:
      -
        ins: Nimrod Aviram
      -
        ins: Benjamin Dowling
      -
        ins: Ilan Komargodski
      -
        ins: Kenny Paterson
      -
        ins: Eyal Ronen
      -
        ins: Eylon Yogev
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security

  DOWLING: DOI.10.1007/s00145-021-09384-1
  FO: DOI.10.1007/s00145-011-9114-1
  HHK: DOI.10.1007/978-3-319-70500-2_12
  HPKE: RFC9180
  hybrid: I-D.ietf-tls-hybrid-design
  KYBERV:
    target: https://eprint.iacr.org/2024/843.pdf
    title: "Formally verifying Kyber Episode V: Machine-checked IND-CCA security and correctness of ML-KEM in EasyCrypt"
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  RACCOON:
    target: https://raccoon-attack.com/
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    author:
    -
      ins: R. Merget
    -
      ins: M. Brinkmann
    -
      ins: N. Aviram
    -
      ins: J. Somorovsky
    -
      ins: J. Mittmann
    -
      ins: J. Schwenk
    date: 2020-09
  RFC9794:
  tlsiana: I-D.ietf-tls-rfc8447bis

--- abstract

This memo defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as `NamedGroup`s
and and registers IANA values in the TLS Supported Groups registry for use
in TLS 1.3 to achieve post-quantum (PQ) key establishment.

--- middle

# Introduction

## Motivation

FIPS 203 (ML-KEM) {{FIPS203}} is a FIPS standard for post-quantum {{RFC9794}}
key establishment via lattice-based key establishment mechanism (KEM). Having
a purely post-quantum (not hybrid) key establishment option for TLS 1.3 is
necessary for migrating beyond hybrids and for users that want or need
post-quantum security without hybrids.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Key encapsulation mechanisms {#kems}

This document models key establishment as key encapsulation mechanisms
(KEMs), which consist of three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
  which generates a public encapsulation key `pk` and a secret
  decapsulation key `sk`.
- `Encaps(pk) -> (ct, shared_secret)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `pk` and
  outputs a ciphertext `ct` and shared secret `shared_secret`.
- `Decaps(sk, ct) -> shared_secret`: A decapsulation algorithm, which takes as
  input a secret decapsulation key `sk` and ciphertext `ct` and outputs
  a shared secret `shared_secret`.


ML-KEM-512, ML-KEM-768 and ML-KEM-1024 conform to this interface:

- ML-KEM-512 has encapsulation keys of size 800 bytes, expanded decapsulation
  keys of 1632 bytes, decapsulation key seeds of size 64 bytes, ciphertext
  size of 768 bytes, and shared secrets of size 32 bytes

- ML-KEM-768 has encapsulation keys of size 1184 bytes, expanded
  decapsulation keys of 2400 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1088 bytes, and shared secrets of size 32 bytes

- ML-KEM-1024 has encapsulation keys of size 1568 bytes, expanded
  decapsulation keys of 3168 bytes, decapsulation key seeds of size 64 bytes,
  ciphertext size of 1568 bytes, and shared secrets of size 32 bytes

# Construction {#construction}

The KEMs are defined as `NamedGroup`s, sent in the `supported_groups`
extension. {{Section 4.2.7 of !RFC8446}}

## Negotiation {#negotiation}

Each parameter set of ML-KEM is assigned an identifier, registered by IANA in
the TLS Supported Groups registry:

~~~
    enum {

         ...,

          /* ML-KEM Key Establishment Methods */
          mlkem512(0x0200),
          mlkem768(0x0201),
          mlkem1024(0x0202)

         ...,

    } NamedGroup;
~~~


## Transmitting encapsulation keys and ciphertexts {#construction-transmitting}

The public encapsulation key and ciphertext values are each
directly encoded with fixed lengths as in {{FIPS203}}.

In TLS 1.3 a KEM public encapsulation key `pk` or ciphertext `ct` is
represented as a `KeyShareEntry` {{Section 4.2.8 of !RFC8446}}:

~~~
    struct {
        NamedGroup group;
        opaque key_exchange<1..2^16-1>;
    } KeyShareEntry;
~~~

These are transmitted in the `extension_data` fields of
`KeyShareClientHello` and `KeyShareServerHello` extensions:

~~~
    struct {
        KeyShareEntry client_shares<0..2^16-1>;
    } KeyShareClientHello;

    struct {
        KeyShareEntry server_share;
    } KeyShareServerHello;
~~~

The `KeyShareClientHello` includes a list of `KeyShareEntry` structs that
represent the key establishment algorithms the client supports. For each
parameter of ML-KEM the client supports, the corresponding `KeyShareEntry`
consists of a `NamedGroup` that indicates the appropriate parameter, and a
`key_exchange` value that is the `pk` output of the `KeyGen` algorithm.

For the client's share, the `key_exchange` value contains the `pk`
output of the corresponding KEM `NamedGroup`'s `KeyGen` algorithm.

For the server's share, the `key_exchange` value contains the `ct`
output of the corresponding KEM `NamedGroup`'s `Encaps` algorithm.

For all parameter sets, the server MUST perform the encapsulation key check
described in Section 7.2 of {{FIPS203}} on the client's encapsulation key,
and abort with an `illegal_parameter` alert if it fails.

For all parameter sets, the client MUST check if the ciphertext length
matches the selected parameter set, and abort with an `illegal_parameter`
alert if it fails.

If ML-KEM decapsulation fails for any other reason, the connection MUST be
aborted with an `internal_error` alert.

## Shared secret calculation {#construction-shared-secret}

The shared secret output from the ML-KEM `Encaps` and `Decaps` algorithms
over the appropriate keypair and ciphertext results in the same shared secret
`shared_secret` as its honest peer, which is inserted into the TLS 1.3 key
schedule in place of the (EC)DHE shared secret, as shown in
{{fig-key-schedule}}.

~~~~
                                    0
                                    |
                                    v
                      PSK ->  HKDF-Extract = Early Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
             shared_secret -> HKDF-Extract = Handshake Secret
             ^^^^^^^^^^^^^          |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    |
                                    v
                              Derive-Secret(., "derived", "")
                                    |
                                    v
                         0 -> HKDF-Extract = Master Secret
                                    |
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
                                    +-----> Derive-Secret(...)
~~~~
{: #fig-key-schedule title="Key schedule for key establishment"}

# Security Considerations {#security-considerations}

## IND-CCA

The main security property for KEMs is indistinguishability under adaptive
chosen ciphertext attack (IND-CCA), which means that shared secret values
should be indistinguishable from random strings even given the ability to
have other arbitrary ciphertexts decapsulated.  IND-CCA corresponds to
security against an active attacker, and the public key / secret key pair can
be treated as a long-term key or reused. ML-KEM satisfies IND-CCA security in
the random oracle model {{KYBERV}}.

TLS 1.3 does not prohibit key re-use; some implementations may use the same
ephemeral public key for more than one key establishment at the cost of
limited forward secrecy. Care must be taken to ensure that keys are only
re-used if the algorithms from which they are derived are designed to be
secure under key-reuse. ML-KEM's IND-CCA security satisfies this requirement
such that the public key/secret key pair can be used long-term or re-used
without compromising the security of the keys. However, it is still
recommended that implementations avoid re-use of any keys (including ML-KEM
keys) to ensure perfect forward secrecy.

Implementations MUST NOT reuse randomness in the generation of ML-KEM
ciphertexts.

## Binding properties

TLS 1.3's key schedule commits to the the ML-KEM encapsulation key and the
ciphertext as the `key_exchange` field as part of the `key_share` extension
are populated with those values are included as part of the handshake
messages, providing resilience against re-encapsulation attacks against KEMs
used for key establishment {{CDM23}}.

# IANA Considerations

This document requests/registers three new entries to the TLS Named Group (or
Supported Group) registry, according to the procedures in {{Section 6 of
tlsiana}}.


 Value:
 : 0x0200

 Description:
 : MLKEM512

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-512



 Value:
 : 0x0201

 Description:
 : MLKEM768

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-768



 Value:
 : 0x0202

 Description:
 : MLKEM1024

 DTLS-OK:
 : Y

 Recommended:
 : N

 Reference:
 : This document

 Comment:
 : FIPS 203 version of ML-KEM-1024


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Douglas Stebila for consultation on the
draft-ietf-tls-hybrid-design design, and to Scott Fluhrer, Eric Rescorla, and
Rebecca Guthrie for reviews.
