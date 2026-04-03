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
  TLSREG:
    target: "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8"
    title: "TLS Supported Groups"
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
  ECDHE-MLKEM: I-D.ietf-tls-ecdhe-mlkem
  HPKE: RFC9180
  HYBRID: I-D.ietf-tls-hybrid-design
  NIST-SP-800-227: DOI.10.6028/NIST.SP.800-227
  RFC9794:
  TLSIANA: I-D.ietf-tls-rfc8447bis

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
ciphertexts, it follows that ML-KEM ciphertexts also MUST NOT be reused.

## Shared secret calculation {#construction-shared-secret}

The fixed-length shared secret output from the ML-KEM `Encaps` and `Decaps`
algorithms over the appropriate keypair and ciphertext results in the same
shared secret `shared_secret` as its peer, which is inserted into the TLS 1.3
key schedule in place of the (EC)DHE shared secret, as shown in {{Section 7.1
of !RFC8446}}.

# Security Considerations {#security-considerations}

{{NIST-SP-800-227}} includes guidelines and requirements for implementations
on using KEMs securely. Implementers are encouraged to use implementations
resistant to side-channel attacks, especially those that can be applied by
remote attackers.

TLS 1.3's key schedule commits to the ML-KEM encapsulation key and the
ciphertext as the `key_exchange` field of the `key_share` extension is
populated with those values, which are included as part of the handshake
messages. This provides resilience against re-encapsulation attacks against
KEMs used for key establishment {{CDM23}}.

This document defines standalone ML-KEM key establishment for TLS 1.3.
A PQ/T hybrid combines
a post-quantum algorithm such as ML-KEM.
with a traditional algorithm such as
Elliptic Curve Diffie-Hellman (ECDH)
The IETF is working on an RFC that defines several such key
establishment mechanisms, ML-KEM with a combining ECDH in {{ECDHE-MLKEM}}.

Both documents have IANA registry entries with an `N` in the recommended
column. Quoting from the registry {{TLSREG}}, "\[this] does not necessarily mean that
it is flawed; rather, it indicates that the item ... has limited
applicability, or is intended only for specific use cases."
Those developing or deploying TLS 1.3 with either encapsulation method
will have to determine the security and operational considerations
when choosing which mechanism to support.

# IANA Considerations

This document requests/registers three new entries to the TLS Named Group (or
Supported Group) registry, according to the procedures in {{Section 6 of
TLSIANA}}.


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
{{HYBRID}} design, and to Scott Fluhrer, Eric Rescorla,
John Mattsson, Martin Thomson, and Rebecca Guthrie for reviews.
Rich Salz wrote the final draft of the security considerations section.
