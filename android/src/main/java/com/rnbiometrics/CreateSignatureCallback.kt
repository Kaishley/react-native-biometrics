package com.rnbiometrics

import android.util.Base64
import androidx.biometric.BiometricPrompt
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableNativeMap
import java.security.Signature

class CreateSignatureCallback(private val promise: Promise, private val payload: String) : BiometricPrompt.AuthenticationCallback() {

  override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
    super.onAuthenticationError(errorCode, errString)
    val resultMap = WritableNativeMap().apply {
      putBoolean("success", false)
      putInt("errorCode", errorCode)
      putString(
        "error",
        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
          "User cancellation"
        } else {
          errString.toString()
        }
      )
    }
    promise.resolve(resultMap)
  }

  override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
    super.onAuthenticationSucceeded(result)

    try {
      val cryptoObject = result.cryptoObject
      val cryptoSignature = cryptoObject?.signature
      cryptoSignature?.update(payload.toByteArray())

      val signed = cryptoSignature?.sign()
      val signedString = signed?.let {
        Base64.encodeToString(it, Base64.DEFAULT)
          .replace("\r", "")
          .replace("\n", "")
      }

      val resultMap = WritableNativeMap().apply {
        putBoolean("success", true)
        putString("signature", signedString)
      }
      promise.resolve(resultMap)
    } catch (e: Exception) {
      promise.reject(e::class.java.simpleName, "Error creating signature: ${e.message}")
    }
  }
}