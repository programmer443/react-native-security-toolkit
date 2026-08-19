// Deliberately insecure fixture.
package com.fixture.vulnerable

import android.util.Log
import java.security.MessageDigest
import javax.crypto.Cipher

object Crypto {
  fun fingerprint(input: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(input)

  fun cipher(): Cipher = Cipher.getInstance("AES")

  fun store(prefs: android.content.SharedPreferences, accessToken: String) {
    prefs.edit().putString("accessToken", accessToken).apply()
    Log.d("Crypto", "stored accessToken=$accessToken")
  }
}
