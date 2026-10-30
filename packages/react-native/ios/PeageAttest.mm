#import <RNPeageAttestSpec/RNPeageAttestSpec.h>

#if __has_include(<PeageReactNative/PeageReactNative-Swift.h>)
#import <PeageReactNative/PeageReactNative-Swift.h>
#else
#import "PeageReactNative-Swift.h"
#endif

@interface PeageAttest : NSObject <NativePeageAttestSpec>
@end

@implementation PeageAttest {
  PeageAttestImpl *_implementation;
}

RCT_EXPORT_MODULE(PeageAttest)

- (instancetype)init
{
  if (self = [super init]) {
    _implementation = [PeageAttestImpl new];
  }
  return self;
}

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (void)isSupported:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_implementation isSupported:resolve reject:reject];
}

- (void)generateKey:(NSString *)clientDataHash
              scope:(NSString *)scope
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [_implementation generateKey:resolve reject:reject];
}

- (void)markAttested:(NSString *)keyId
               scope:(NSString *)scope
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  [_implementation markAttested:keyId scope:scope resolve:resolve reject:reject];
}

- (void)getKeyId:(NSString *)scope
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  [_implementation getKeyId:scope resolve:resolve reject:reject];
}

- (void)clearKeyId:(NSString *)scope
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  [_implementation clearKeyId:scope resolve:resolve reject:reject];
}

- (void)attestKey:(NSString *)keyId
   clientDataHash:(NSString *)clientDataHash
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [_implementation attestKey:keyId clientDataHash:clientDataHash resolve:resolve reject:reject];
}

- (void)generateAssertion:(NSString *)keyId
           clientDataHash:(NSString *)clientDataHash
                  resolve:(RCTPromiseResolveBlock)resolve
                   reject:(RCTPromiseRejectBlock)reject
{
  [_implementation generateAssertion:keyId
                      clientDataHash:clientDataHash
                             resolve:resolve
                              reject:reject];
}

- (void)sha256:(NSString *)data
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject
{
  [_implementation sha256:data resolve:resolve reject:reject];
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativePeageAttestSpecJSI>(params);
}

@end
