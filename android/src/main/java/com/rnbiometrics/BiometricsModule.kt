package com.rnbiometrics

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.*
import java.security.*
import java.security.spec.RSAKeyGenParameterSpec
import java.util.concurrent.Executors

class BiometricsModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String {
    return NAME
  }

  companion object {
    const val NAME = "Biometrics"
  }

  private val biometricKeyAlias = "biometric_key"

  private var biometricPrompt: BiometricPrompt? = null

  @ReactMethod
  fun isSensorAvailable(params: ReadableMap, promise: Promise) {
    try {
      if (isCurrentSDKMarshmallowOrLater()) {
        val allowDeviceCredentials = params.getBoolean("allowDeviceCredentials")
        val reactApplicationContext = reactApplicationContext
        val biometricManager = BiometricManager.from(reactApplicationContext)
        val canAuthenticate = biometricManager.canAuthenticate(getAllowedAuthenticators(allowDeviceCredentials))

        val resultMap = WritableNativeMap()
        if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
          resultMap.putBoolean("available", true)
          resultMap.putString("biometryType", "Biometrics")
          promise.resolve(resultMap)
        } else {
          resultMap.putBoolean("available", false)
          resultMap.putInt("errorCode", canAuthenticate)
          when (canAuthenticate) {
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> resultMap.putString("error", "BIOMETRIC_ERROR_NO_HARDWARE")
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> resultMap.putString("error", "BIOMETRIC_ERROR_HW_UNAVAILABLE")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> resultMap.putString("error", "BIOMETRIC_ERROR_NONE_ENROLLED")
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> resultMap.putString("error", "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED")
          }
          promise.resolve(resultMap)
        }
      } else {
        val resultMap = WritableNativeMap()
        resultMap.putBoolean("available", false)
        resultMap.putString("error", "Unsupported android version")
        promise.resolve(resultMap)
      }
    } catch (e: Exception) {
      promise.reject(e::class.java.simpleName, "Error detecting biometrics availability: ${e.message}")
    }
  }

  @ReactMethod
  fun createKeys(params: ReadableMap, promise: Promise) {
    try {
      if (isCurrentSDKMarshmallowOrLater()) {
        deleteBiometricKey()
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(biometricKeyAlias, KeyProperties.PURPOSE_SIGN)
          .setDigests(KeyProperties.DIGEST_SHA256)
          .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
          .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
          .setUserAuthenticationRequired(true)
          .build()
        keyPairGenerator.initialize(keyGenParameterSpec)

        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public
        val encodedPublicKey = publicKey.encoded
        var publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT)
        publicKeyString = publicKeyString.replace("\r", "").replace("\n", "")

        val resultMap = WritableNativeMap() 
        resultMap.putString("publicKey", publicKeyString)
        promise.resolve(resultMap)
      } else {
        promise.reject("ANDROID_VERSION_NOT_SUPPORTED", "Cannot generate keys on android versions below 6.0")
      }
    } catch (e: Exception) {
      promise.reject(e::class.java.simpleName, "Error generating public private keys")
    }
  }

  @ReactMethod
  fun deleteKeys(promise: Promise) {
    if (doesBiometricKeyExist()) {
      val deletionSuccessful = deleteBiometricKey()

      if (deletionSuccessful) {
        val resultMap = WritableNativeMap()
        resultMap.putBoolean("keysDeleted", true)
        promise.resolve(resultMap)
      } else {
        promise.reject("DELETE_KEYS_FAILED", "Error deleting biometric key from keystore")
      }
    } else {
      val resultMap = WritableNativeMap()
      resultMap.putBoolean("keysDeleted", false)
      promise.resolve(resultMap)
    }
  }

  @ReactMethod
  fun createSignature(params: ReadableMap, promise: Promise) {
    if (isCurrentSDKMarshmallowOrLater()) {
      UiThreadUtil.runOnUiThread {
        try {
          val promptMessage = params.getString("promptMessage")
          val payload = params.getString("payload")
          val cancelButtonText = params.getString("cancelButtonText")
          val allowDeviceCredentials = params.getBoolean("allowDeviceCredentials")

          val signature = Signature.getInstance("SHA256withRSA")
          val keyStore = KeyStore.getInstance("AndroidKeyStore")
          keyStore.load(null)

          val privateKey = keyStore.getKey(biometricKeyAlias, null) as PrivateKey
          signature.initSign(privateKey)

          val cryptoObject = BiometricPrompt.CryptoObject(signature)

          val authCallback = CreateSignatureCallback(promise, payload!!)
          val fragmentActivity = currentActivity as FragmentActivity?
          val executor = Executors.newSingleThreadExecutor()
          
          // Store the biometric prompt instance at a class level so that it can be accessed by `cancelPrompt`
          biometricPrompt = BiometricPrompt(fragmentActivity!!, executor, authCallback)


          biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials), cryptoObject)
        } catch (e: Exception) {
          promise.reject(e::class.java.simpleName, "Error generating signature: ${e.message}")
        }
      }
    } else {
      promise.reject("ANDROID_VERSION_NOT_SUPPORTED", "Cannot generate keys on android versions below 6.0")
    }
  }

  @ReactMethod
  fun simplePrompt(params: ReadableMap, promise: Promise) {
    if (isCurrentSDKMarshmallowOrLater()) {
      UiThreadUtil.runOnUiThread {
        try {
          val promptMessage = params.getString("promptMessage")
          val cancelButtonText = params.getString("cancelButtonText")
          val allowDeviceCredentials = params.getBoolean("allowDeviceCredentials")

          val authCallback = SimplePromptCallback(promise)
          val fragmentActivity = currentActivity as FragmentActivity?
          val executor = Executors.newSingleThreadExecutor()

          // Store the biometric prompt instance at a class level so that it can be accessed by `cancelPrompt`
          biometricPrompt = BiometricPrompt(fragmentActivity!!, executor, authCallback)

          biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials))
        } catch (e: Exception) {
          promise.reject(e::class.java.simpleName, "Error displaying local biometric prompt: ${e.message}")
        }
      }
    } else {
      promise.reject("ANDROID_VERSION_NOT_SUPPORTED", "Cannot display biometric prompt on android versions below 6.0")
    }
  }

  @ReactMethod
  fun cancelPrompt(promise: Promise) {
    if (isCurrentSDKMarshmallowOrLater()) {
      UiThreadUtil.runOnUiThread {
        try {
          biometricPrompt?.cancelAuthentication()
          promise.resolve("Biometric authentication cancelled")
        } catch (e: Exception) {
          promise.reject(e::class.java.simpleName, "Error cancelling biometric authentication: ${e.message}")
        }
      }
    } else {
      promise.reject("ANDROID_VERSION_NOT_SUPPORTED", "Android versions below 6.0 do not support biometrics")
    }
  }

  @ReactMethod
  fun biometricKeysExist(promise: Promise) {
    try {
      val doesBiometricKeyExist = doesBiometricKeyExist()
      val resultMap = WritableNativeMap()
      resultMap.putBoolean("keysExist", doesBiometricKeyExist)
      promise.resolve(resultMap)
    } catch (e: Exception) {
      promise.reject(e::class.java.simpleName, "Error checking if biometric key exists: ${e.message}")
    }
  }

  private fun isCurrentSDKMarshmallowOrLater(): Boolean {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
  }

  private fun isCurrentSDK29OrEarlier(): Boolean {
    return Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q
  }

  private fun doesBiometricKeyExist(): Boolean {
    return try {
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      keyStore.containsAlias(biometricKeyAlias)
    } catch (e: Exception) {
      false
    }
  }

  private fun deleteBiometricKey(): Boolean {
    return try {
      val keyStore = KeyStore.getInstance("AndroidKeyStore")
      keyStore.load(null)
      keyStore.deleteEntry(biometricKeyAlias)
      true
    } catch (e: Exception) {
      false
    }
  }

  private fun getPromptInfo(promptMessage: String?, cancelButtonText: String?, allowDeviceCredentials: Boolean): BiometricPrompt.PromptInfo {
    val builder = BiometricPrompt.PromptInfo.Builder().setTitle(promptMessage ?: "")

    builder.setAllowedAuthenticators(getAllowedAuthenticators(allowDeviceCredentials))

    if (!allowDeviceCredentials || isCurrentSDK29OrEarlier()) {
      builder.setNegativeButtonText(cancelButtonText ?: "")
    }

    return builder.build()
  }

  private fun getAllowedAuthenticators(allowDeviceCredentials: Boolean): Int {
    return if (allowDeviceCredentials && !isCurrentSDK29OrEarlier()) {
      BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    }
  }
}