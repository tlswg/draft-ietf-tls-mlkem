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
  CHSW22:
    target: https://doi.org/10.1007/978-3-031-17143-7_4
    title: "A Tale of Two Models: Formal Verification of KEMTLS via Tamarin"
    date: 2022
    seriesinfo: "Proceedings of ESORICS 2022"
    author:
    -
      ins: S. Celi
    -
      ins: J. Hoyland
    -
      ins: D. Stebila
    -
      ins: T. Wiggers
  CNSAFAQ:
    target: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
    title: "The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ"
  CNSSP15:
    target: https://www.cnss.gov/CNSS/openDoc.cfm?a=kryrfZb9nS00l4L2shjYcQ%3D%3D&b=C944BD2E7ABAA37851D7A7EF71743C3ACE8393115D7588CD4423DD2B918812A86F060A05C2E0D4DEF8456CC75B2D39F4
    title: "USE OF PUBLIC STANDARDS FOR SECURE INFORMATION SHARING"
  CZCJWH25:
    target: https://eprint.iacr.org/2025/1748.pdf
    title: "Post-Quantum {TLS} 1.3 Handshake from {CPA}-Secure {KEMs} with Tighter Reductions"
  DOWLING:
    target: DOI.10.1007/s00145-021-09384-1
    title: "A Cryptographic Analysis of the TLS 1.3 Handshake Protocol"
    date: 2020
    seriesinfo: "Journal of Cryptology 2021"
  ECDHE-MLKEM: I-D.ietf-tls-ecdhe-mlkem
  FO: DOI.10.1007/s00145-011-9114-1
  GHS25:
    target: https://eprint.iacr.org/2025/343.pdf
    title: "On The Multi-target Security of Post-Quantum Key Encapsulation Mechanisms"
    date: 2025
    seriesinfo: "Cryptology ePrint Archive, Report 2025/343"
    author:
    -
      name: Lewis Glabush
    -
      name: Kathrin Hovelmanns
    -
      name: Douglas Stebila
  HHK: DOI.10.1007/978-3-319-70500-2_12
  HV22:
    target: https://link.springer.com/chapter/10.1007/978-3-031-07082-2_22
    title: "On IND-qCCA Security in the ROM and Its Applications - CPA Security Is Sufficient for TLS 1.3"
    seriesinfo: Proceedings of Eurocrypt 2022
    author:
    -
      name: Loïs Huguenin-Dumittan
    -
      name: Serge Vaudenay
  HPKE: RFC9180
  HYBRID: I-D.ietf-tls-hybrid-design
  ITSP.40.111:
    target: "https://www.cyber.gc.ca/en/guidance/cryptographic-algorithms-unclassified-protected-protected-b-information-itsp40111#a54"
    title: "Cryptographic algorithms for UNCLASSIFIED, PROTECTED A, and PROTECTED B information - ITSP.40.111"
  KEMTLS: DOI.10.1145/3372297.3423350
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
  NIST-SP-800-227: DOI.10.6028/NIST.SP.800-227
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
  RFC8446bis: I-D.ietf-tls-rfc8446obis
  tlsiana: I-D.ietf-tls-rfc8447bis
  ZJZ24:
    target: https://doi.org/10.1007/978-981-96-0891-1_14

    title: "CPA-Secure KEMs are also Sufficient for Post-quantum TLS 1.3"
    seriesinfo: Proceedings of Asiacrypt 2024
    author:
    -
      ins: B. Zhou
    -
      ins: H.Jiang
    -
      ins: Y. Zhao

--- abstract

This memo defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as `NamedGroup`s
and and registers IANA values in the TLS Supported Groups registry for use
in TLS 1.3 to achieve post-quantum (PQ) key establishment.

--- middle

# Introduction

ML-KEM {{FIPS203}} is a FIPS standard for post-quantum {{RFC9794}} key
establishment via a lattice-based key encapsulation mechanism (KEM). This
document defines key establishment options for TLS 1.3 via the existing
`supported_groups` {{Section 4.2.7 of !RFC8446bis}} and `key_share` {{Section
4.2.8 of !RFC8446bis}} extensions.

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
represented as a `KeyShareEntry` as specified in {{Section 4.2.8 of
!RFC8446}}. These are transmitted in the `extension_data` fields of
`KeyShareClientHello` and `KeyShareServerHello` extensions.

For the client's share, the `key_exchange` value contains the `pk`
output of the corresponding ML-KEM parameter set's `KeyGen` algorithm.

For the server's share, the `key_exchange` value contains the `ct`
output of the corresponding ML-KEM parameter set's `Encaps` algorithm.

For all parameter sets, the server MUST perform the encapsulation key check
described in Section 7.2 of {{FIPS203}} on the client's encapsulation key,
and abort with an `illegal_parameter` alert if it fails.

For all parameter sets, the client MUST check if the ciphertext length
matches the selected parameter set, and abort with an `illegal_parameter`
alert if it fails.

If ML-KEM decapsulation fails for any other reason, the connection MUST be
aborted with an `internal_error` alert.

Implementations MUST NOT reuse randomness in the generation of ML-KEM
ciphertexts— it follows that ML-KEM ciphertexts also MUST NOT be reused.

## Shared secret calculation {#construction-shared-secret}

The fixed-length shared secret output from the ML-KEM `Encaps` and `Decaps`
algorithms over the appropriate keypair and ciphertext results in the same
shared secret `shared_secret` as its peer, which is inserted into the TLS 1.3
key schedule in place of the (EC)DHE shared secret, as shown in {{Section 7.1
of !RFC8446}}.

# Security Considerations {#security-considerations}

This document defines standalone ML-KEM key establishment for TLS 1.3.
Hybrid key establishment mechanisms, which support combining a post-quantum
algorithm with a traditional algorithm such as ECDH, are supported
generically via {{HYBRID}} with some concrete definitions in
{{ECDHE-MLKEM}}. Hybrid mechanisms provide security as long as at least one
of the component algorithms remains unbroken, such as combining
quantum-resistant and traditional cryptographic assumptions. Standalone
ML-KEM relies on lattice-based and hash function cryptographic assumptions
for its security. Proponents of hybrid PQ/T key establishment generally
consider it a conservative approach to deployment of newer post-quantum
schemes alongside older traditional schemes, retaining at least the security
currently offered by traditional algorithms.

The main security property for KEMs is indistinguishability under adaptive
chosen ciphertext attack (IND-CCA), which means that shared secret values
should be indistinguishable from random strings even given the ability to
have other arbitrary ciphertexts decapsulated. IND-CCA corresponds to
security against an active attacker, and the public encapsulation key /
secret decapsulation key pair can be treated as a long-term key or reused in
generic usage. ML-KEM satisfies IND-CCA security in the random oracle model
{{KYBERV}} via a variant of the Fujisaki-Okamoto (FO) transform
{{FO}}{{HHK}}. Use of KEMs for key agreement in TLS 1.3 has been analyzed and
discussed in multiple settings and security models {{DOWLING}} {{KEMTLS}}
{{HV22}} {{CHSW22}} {{CZCJWH25}} {{ZJZ24}}: ML-KEM's IND-CCA security exceeds
the requirements for ephemeral key establishment and secure in case of reuse
{{GHS25}} {{RFC8446bis}}.

{{NIST-SP-800-227}} includes guidelines and requirements for implementations
on using KEMs securely. Implementers are encouraged to use implementations
resistant to side-channel attacks, especially those that can be applied by
remote attackers.

TLS 1.3's key schedule commits to the ML-KEM encapsulation key and the
ciphertext as the `key_exchange` field of the `key_share` extension is
populated with those values, which are included as part of the handshake
messages. This provides resilience against re-encapsulation attacks against
KEMs used for key establishment {{CDM23}}.

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
draft-ietf-tls-hybrid-design design, and to Scott Fluhrer, Eric Rescorla,
John Mattsson, Martin Thomson, and Rebecca Guthrie for reviews.
