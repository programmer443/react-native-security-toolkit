package com.fixture.secure

import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import java.security.MessageDigest
import javax.crypto.Cipher

object Crypto {
  fun fingerprint(input: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(input)

  fun cipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

  fun store(prefs: EncryptedSharedPreferences, accessToken: String) {
    prefs.edit().putString("accessToken", accessToken).apply()
    Log.d("Crypto", "stored session for user")
  }
}
