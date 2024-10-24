#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Biometrics, NSObject)

RCT_EXTERN_METHOD(isSensorAvailable: (NSDictionary *) params resolver:(RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

RCT_EXTERN_METHOD(createKeys: (NSDictionary *) params resolver:(RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

RCT_EXTERN_METHOD(deleteKeys: (RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

RCT_EXTERN_METHOD(createSignature: (NSDictionary *) params resolver:(RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

RCT_EXTERN_METHOD(simplePrompt: (NSDictionary *) params resolver:(RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

RCT_EXTERN_METHOD(cancelPrompt)

RCT_EXTERN_METHOD(biometricKeysExist: (RCTPromiseResolveBlock) resolve rejecter:(RCTPromiseRejectBlock) reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
