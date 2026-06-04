package com.example.pocketsshagent.agent

import android.util.Base64
import java.security.MessageDigest
import java.security.PublicKey

object SshPublicKeyUtils {

    fun formatAuthorizedKeysLine(publicKey: PublicKey, comment: String): String {
        val enc = publicKey.encoded
        val (keyType, keyBlob) = when {
            SshWireFormat.isEd25519PublicKey(enc) -> {
                val raw = SshWireFormat.extractRawEd25519PublicKey(enc)
                "ssh-ed25519" to SshWireFormat.encodeEd25519PublicKey(raw)
            }
            SshWireFormat.isP256PublicKey(enc) -> {
                val raw = SshWireFormat.extractRawP256PublicKey(enc)
                "ecdsa-sha2-nistp256" to SshWireFormat.encodeEcdsaP256PublicKey(raw)
            }
            else -> throw IllegalArgumentException("Unsupported key type")
        }
        val encoded = Base64.encodeToString(keyBlob, Base64.NO_WRAP)
        return "$keyType $encoded $comment"
    }

    fun fingerprint(publicKey: PublicKey): String {
        val enc = publicKey.encoded
        val keyBlob = when {
            SshWireFormat.isEd25519PublicKey(enc) -> {
                val raw = SshWireFormat.extractRawEd25519PublicKey(enc)
                SshWireFormat.encodeEd25519PublicKey(raw)
            }
            SshWireFormat.isP256PublicKey(enc) -> {
                val raw = SshWireFormat.extractRawP256PublicKey(enc)
                SshWireFormat.encodeEcdsaP256PublicKey(raw)
            }
            else -> throw IllegalArgumentException("Unsupported key type")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(keyBlob)
        val encoded = Base64.encodeToString(digest, Base64.NO_WRAP or Base64.NO_PADDING)
        return "SHA256:$encoded"
    }
}
