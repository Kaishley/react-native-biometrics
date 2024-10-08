package com.rnbiometrics

import androidx.biometric.BiometricPrompt
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.WritableNativeMap

class SimplePromptCallback(private val promise: Promise) : BiometricPrompt.AuthenticationCallback() {

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
    val resultMap = WritableNativeMap().apply {
      putBoolean("success", true)
    }
    promise.resolve(resultMap)
  }
}