import LocalAuthentication

@objc(Biometrics)
class Biometrics: NSObject {

  var authenticationContext: LAContext?


  @objc
  func isSensorAvailable(_ params: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
      let context = LAContext()
      var laError: NSError?
      var laPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
      let allowDeviceCredentials = params["allowDeviceCredentials"] as? Bool ?? false
      
      if allowDeviceCredentials {
          laPolicy = .deviceOwnerAuthentication
      }
      
      let canEvaluatePolicy = context.canEvaluatePolicy(laPolicy, error: &laError)
      
      if canEvaluatePolicy {
          let biometryType = getBiometryType(context: context)
          let result: [String: Any] = [
              "available": true,
              "biometryType": biometryType
          ]
          resolve(result)
      } else {
          let errorMessage = laError?.localizedDescription ?? "Unknown error"
          let result: [String: Any] = [
              "available": false,
              "error": errorMessage,
              "errorCode": laError?.code ?? -1
          ]
          resolve(result)
      }
  }
  
  @objc
  func createKeys(_ params: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
      let allowDeviceCredentials = params["allowDeviceCredentials"] as? Bool ?? false
    
      DispatchQueue.global(qos: .default).async {
          var error: Unmanaged<CFError>?
          
          let accessControl = SecAccessControlCreateWithFlags(
              kCFAllocatorDefault,
              kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
              allowDeviceCredentials ? .userPresence : .biometryAny,
              &error
          )
          
          if accessControl == nil || error != nil {
              let errorString = "SecItemAdd can't create sacObject: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")"
              reject("storage_error", errorString, nil)
              return
          }
          
          let biometricKeyTag = self.getBiometricKeyTag()
          let keyAttributes: [String: Any] = [
              kSecClass as String: kSecClassKey,
              kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
              kSecAttrKeySizeInBits as String: 2048,
              kSecPrivateKeyAttrs as String: [
                  kSecAttrIsPermanent as String: true,
                  kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                  kSecAttrApplicationTag as String: biometricKeyTag,
                  kSecAttrAccessControl as String: accessControl!
              ]
          ]
          
          self.deleteBiometricKey()
          var genError: Unmanaged<CFError>?
          guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &genError) else {
              let message = "Key generation error: \(genError?.takeRetainedValue().localizedDescription ?? "Unknown error")"
              reject("storage_error", message, nil)
              return
          }
          
          guard let publicKey = SecKeyCopyPublicKey(privateKey),
                let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data else {
              reject("storage_error", "Failed to get public key data", nil)
              return
          }
        
        let publicKeyDataWithHeader = self.addHeaderPublicKey(publicKeyData)
          
          let publicKeyString = publicKeyDataWithHeader.base64EncodedString()
//          self.storePolicyDomainState() // TODO
          
          let result: [String: Any] = [
              "publicKey": publicKeyString
          ]
          resolve(result)
      }
  }
  
  @objc
  func deleteKeys(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
      DispatchQueue.global(qos: .default).async {
          let biometricKeyExists = self.doesBiometricKeyExist()
          
          if !biometricKeyExists {
              let result: [String: Any] = [
                  "keysDeleted": false
              ]
              resolve(result)
              return
          }
          
          let status = self.deleteBiometricKey()
          if status != errSecSuccess {
              let errorMessage = (SecCopyErrorMessageString(status, nil) as String?) ?? "Unknown error"
              reject(String(status), errorMessage, nil)
              return
          }
          
          let result: [String: Any] = [
              "keysDeleted": true
          ]
          resolve(result)
      }
  }
  
  @objc
  func createSignature(_ params: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let promptMessage = params["promptMessage"] as! String
    let rawPayload = params["payload"] as! String
    
      DispatchQueue.global(qos: .default).async {
        // TODO
//          let hasPolicyDomainStateChanged = self.hasPolicyDomainStateChanged()
//          
//          if hasPolicyDomainStateChanged {
//              let result: [String: Any] = [
//                  "success": false,
//                  "error": "Biometrics changed",
//                  "errorCode": "BIOMETRICS_CHANGED"
//              ]
//              resolve(result)
//              return
//          }

          // Store the `LAContext` object at a class level so that it can be accessed by `cancelPrompt`
          self.authenticationContext = LAContext()
          guard let context = self.authenticationContext else { return }
          
          context.localizedFallbackTitle = ""
          
          context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: promptMessage) { success, laError in
              if !success {
                  let message = laError?.localizedDescription ?? "Unknown error"
                  let result: [String: Any] = [
                      "success": false,
                      "error": (laError as? NSError)?.code == LAError.userCancel.rawValue ? "User cancellation" : message,
                      "errorCode": (laError as? NSError)?.code ?? -1
                  ]
                  resolve(result)
                  return
              }
              
              let biometricKeyTag = self.getBiometricKeyTag()
              
              let query: [String: Any] = [
                  kSecClass as String: kSecClassKey,
                  kSecAttrApplicationTag as String: biometricKeyTag,
                  kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                  kSecReturnRef as String: true,
                  kSecUseAuthenticationContext as String: context
              ]
              
              var item: CFTypeRef?
              let status = SecItemCopyMatching(query as CFDictionary, &item)
              
              guard status == errSecSuccess, let privateKey = item as! SecKey? else {
                  let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "Unknown error"
                  let result: [String: Any] = [
                      "success": false,
                      "error": message,
                      "errorCode": status
                  ]
                  resolve(result)
                  return
              }
              
              guard let payload = rawPayload.data(using: .utf8),
                    let signature = SecKeyCreateSignature(
                        privateKey,
                        .rsaSignatureMessagePKCS1v15SHA256,
                        payload as CFData,
                        nil
                    ) as Data? else {
                  reject("sign_error", "Failed to create signature", nil)
                  return
              }
              
              let signatureString = signature.base64EncodedString()
              let result: [String: Any] = [
                  "success": true,
                  "signature": signatureString
              ]
              resolve(result)
          }
      }
  }
  
  @objc
  func simplePrompt(_ params: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let allowDeviceCredentials = params["allowDeviceCredentials"] as? Bool ?? false
    let promptMessage = params["promptMessage"] as! String
    let fallbackPromptMessage = params["fallbackPromptMessage"] as! String

    DispatchQueue.global(qos: .default).async {
          // Store the `LAContext` object at a class level so that it can be accessed by `cancelPrompt`
          self.authenticationContext = LAContext()
          guard let context = self.authenticationContext else { return }

          let laPolicy: LAPolicy = allowDeviceCredentials ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
          context.localizedFallbackTitle = allowDeviceCredentials ? fallbackPromptMessage : ""

          context.evaluatePolicy(laPolicy, localizedReason: promptMessage) { success, error in
              if !success {
                  let message = error?.localizedDescription ?? "Unknown error"
                  let result: [String: Any] = [
                      "success": false,
                      "error": (error as NSError?)?.code == LAError.userCancel.rawValue ? "User cancellation" : message,
                      "errorCode": (error as NSError?)?.code ?? -1
                  ]
                  resolve(result)
                  return
              }

              let result: [String: Any] = [
                  "success": true
              ]
              resolve(result)
          }
      }
  }

  @objc
  func cancelPrompt() {
    DispatchQueue.main.async {
      authenticationContext?.invalidate()
      authenticationContext = nil
    }
  }
  
  @objc
  func biometricKeysExist(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
      DispatchQueue.global(qos: .default).async {
          let biometricKeyExists = self.doesBiometricKeyExist()
          let result: [String: Any] = [
              "keysExist": biometricKeyExists
          ]
          resolve(result)
      }
  }

  private func getPolicyDomainStateTag() -> String {
      return "com.rnbiometrics.evaluatedPolicyDomainState"
  }

  private func storePolicyDomainState() {
      let context = LAContext()
      var laError: NSError?
      let laPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

      let canEvaluatePolicy = context.canEvaluatePolicy(laPolicy, error: &laError)

      if canEvaluatePolicy, let evaluatedState = context.evaluatedPolicyDomainState {
          let current = evaluatedState.base64EncodedString()
          let policyDomainStateTag = getPolicyDomainStateTag()

          let query: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrService as String: policyDomainStateTag,
              kSecValueData as String: current
          ]

          // Delete any existing item for the key
          SecItemDelete(query as CFDictionary)

          // Add the new item to the keychain
          SecItemAdd(query as CFDictionary, nil)
      }
  }

  private func hasPolicyDomainStateChanged() -> Bool {
      let context = LAContext()
      var laError: NSError?
      let laPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

      let canEvaluatePolicy = context.canEvaluatePolicy(laPolicy, error: &laError)

      if canEvaluatePolicy, let evaluatedState = context.evaluatedPolicyDomainState {
          let current = evaluatedState.base64EncodedString()
          let policyDomainStateTag = getPolicyDomainStateTag()

          let query: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrService as String: policyDomainStateTag,
              kSecReturnData as String: kCFBooleanTrue as Any
          ]

          var result: AnyObject?
          let status = SecItemCopyMatching(query as CFDictionary, &result)

          if status != errSecSuccess {
              return true
          }

          if let resultData = result as? Data,
             let storedState = String(data: resultData, encoding: .utf8) {
              return storedState != current
          }

          return true
      } else {
          return true
      }
  }

  private func getBiometricKeyTag() -> Data {
      let biometricKeyAlias = "com.rnbiometrics.biometricKey"
      return biometricKeyAlias.data(using: .utf8)!
  }

  private func doesBiometricKeyExist() -> Bool {
      let biometricKeyTag = getBiometricKeyTag()
      let searchQuery: [String: Any] = [
          kSecClass as String: kSecClassKey,
          kSecAttrApplicationTag as String: biometricKeyTag,
          kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
          kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
      ]

      let status = SecItemCopyMatching(searchQuery as CFDictionary, nil)
      return status == errSecSuccess || status == errSecInteractionNotAllowed
  }

  private func deleteBiometricKey() -> OSStatus {
      let biometricKeyTag = getBiometricKeyTag()
      let deleteQuery: [String: Any] = [
          kSecClass as String: kSecClassKey,
          kSecAttrApplicationTag as String: biometricKeyTag,
          kSecAttrKeyType as String: kSecAttrKeyTypeRSA
      ]

      return SecItemDelete(deleteQuery as CFDictionary)
  }

  private func getBiometryType(context: LAContext) -> String {
      if #available(iOS 11, *) {
          return context.biometryType == .faceID ? "FaceID" : "TouchID"
      }
      return "TouchID"
  }

  private func addHeaderPublicKey(_ publicKeyData: Data) -> Data {
      var builder = [UInt8](repeating: 0, count: 15)
      let encKey = NSMutableData()
      let bitstringEncLength: Int

      let encodedRSAEncryptionOID: [UInt8] = [
          0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
          0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
      ]

      if publicKeyData.count + 1 < 128 {
          bitstringEncLength = 1
      } else {
          bitstringEncLength = (publicKeyData.count + 1) / 256 + 2
      }

      builder[0] = 0x30 // ASN.1 SEQUENCE
      let i = encodedRSAEncryptionOID.count + 2 + bitstringEncLength + publicKeyData.count
      let j = encodeLength(&builder[1], length: i)
      encKey.append(builder, length: j + 1)

      encKey.append(encodedRSAEncryptionOID, length: encodedRSAEncryptionOID.count)

      builder[0] = 0x03 // BIT STRING
      let k = encodeLength(&builder[1], length: publicKeyData.count + 1)
      builder[k + 1] = 0x00
      encKey.append(builder, length: k + 2)

      encKey.append(publicKeyData)

      return encKey as Data
  }

  private func encodeLength(_ buffer: UnsafeMutablePointer<UInt8>, length: Int) -> Int {
      if length < 128 {
          buffer[0] = UInt8(length)
          return 1
      }

      var length = length
      let i = (length / 256) + 1
      buffer[0] = UInt8(i + 0x80)

      for j in 0..<i {
          buffer[i - j] = UInt8(length & 0xFF)
          length >>= 8
      }

      return i + 1
  }
}
