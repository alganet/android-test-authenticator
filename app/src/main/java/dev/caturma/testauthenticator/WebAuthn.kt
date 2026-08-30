package dev.caturma.testauthenticator

import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

/* The bytes a relying party actually checks.
 *
 * Everything a verifier looks at is assembled here: the authenticator data,
 * the COSE key inside it, and the attestation object that carries both. The
 * signing itself is Keystore's -- see Vault -- because a key this file could
 * hold would be a key that never had to be in hardware.
 *
 * Attestation is `none`, which is what a platform authenticator sends by
 * default and the only sensible answer for a thing whose whole purpose is to
 * be run by whoever cloned it. There is no meaningful claim to make about
 * hardware here and pretending otherwise would be the one lie a test
 * authenticator must not tell. */
object WebAuthn {

  /* Sixteen zero bytes. AAGUID identifies an authenticator model, and a
     platform authenticator with attestation `none` is required to send
     zeros -- the model is exactly what `none` declines to reveal. */
  val AAGUID = ByteArray(16)

  object Flags {
    const val UP = 0x01      // user present
    const val UV = 0x04      // user verified
    const val BE = 0x08      // backup eligible
    const val BS = 0x10      // backup state
    const val AT = 0x40      // attested credential data included
  }

  fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

  /* rpIdHash | flags | signCount | [attestedCredentialData]
   *
   * BE and BS stay clear and that is a real statement, not an omission: a
   * key in this device's Keystore cannot be backed up or synced anywhere,
   * so claiming otherwise would make the assertion describe a different
   * authenticator. A verifier that refuses `backed up but not eligible` --
   * the combination that cannot exist -- is right to, and this must never
   * produce it. */
  fun authenticatorData(
    rpId: String,
    flags: Int,
    signCount: Long,
    attested: ByteArray? = null,
  ): ByteArray {
    val head = sha256(rpId.toByteArray(Charsets.UTF_8)) +
      byteArrayOf(flags.toByte()) +
      byteArrayOf(
        (signCount shr 24).toByte(), (signCount shr 16).toByte(),
        (signCount shr 8).toByte(), signCount.toByte(),
      )
    return if (attested == null) head else head + attested
  }

  /* aaguid | credentialIdLength | credentialId | COSE public key */
  fun attestedCredentialData(credentialId: ByteArray, key: ECPublicKey): ByteArray =
    AAGUID +
      byteArrayOf((credentialId.size shr 8).toByte(), credentialId.size.toByte()) +
      credentialId +
      cosePublicKey(key)

  /* COSE_Key for ES256 over P-256, in the label order RFC 8152 gives:
     kty(1)=2, alg(3)=-7, crv(-1)=1, x(-2), y(-3). A verifier that reads
     this by label does not care about order; one that hashes the encoding
     does, and there is no reason to be the party that finds out which. */
  fun cosePublicKey(key: ECPublicKey): ByteArray {
    val p: ECPoint = key.w
    /* The labels are the numbers themselves -- -1, -2, -3 -- not the CBOR
       argument that encodes them. Passing 0, 1, 2 here reads as the right
       thing and encodes as something else entirely, and the resulting key
       still parses far enough to fail as `bad_attestation` on a server
       rather than as anything that names a label. Cbor.nint takes the
       value; CborTest pins that. */
    return Cbor.map(
      listOf(
        Cbor.uint(1) to Cbor.uint(2),         // kty: EC2
        Cbor.uint(3) to Cbor.nint(-7),        // alg: ES256
        Cbor.nint(-1) to Cbor.uint(1),        // crv: P-256
        Cbor.nint(-2) to Cbor.bytes(coord(p.affineX)),
        Cbor.nint(-3) to Cbor.bytes(coord(p.affineY)),
      ),
    )
  }

  /* Exactly 32 bytes, left-padded. BigInteger.toByteArray() adds a leading
     zero whenever the high bit is set and drops leading zeros otherwise, so
     roughly one key in two comes out the wrong length if this is skipped --
     which fails as a signature mismatch on the server, a long way from
     here. */
  private fun coord(v: java.math.BigInteger): ByteArray {
    val raw = v.toByteArray()
    return when {
      raw.size == 32 -> raw
      raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
      else -> ByteArray(32 - raw.size) + raw
    }
  }

  /* { fmt: "none", attStmt: {}, authData: bytes } -- and the key order is
     the one every implementation writes, so it is the one written here. */
  fun attestationObject(authData: ByteArray): ByteArray =
    Cbor.map(
      listOf(
        Cbor.text("fmt") to Cbor.text("none"),
        Cbor.text("attStmt") to Cbor.map(emptyList()),
        Cbor.text("authData") to Cbor.bytes(authData),
      ),
    )

  /* What gets signed, for both registration and assertion. */
  fun signedOver(authData: ByteArray, clientDataJson: ByteArray): ByteArray =
    authData + sha256(clientDataJson)
}
