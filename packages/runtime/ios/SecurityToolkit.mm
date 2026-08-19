#import "SecurityToolkit.h"
#import "SecurityToolkitVersion.h"

// The Swift half of the module. Which umbrella import form resolves depends on
// whether the pod is built as a framework or a static library, so try both.
#if __has_include(<SecurityToolkit/SecurityToolkit-Swift.h>)
#import <SecurityToolkit/SecurityToolkit-Swift.h>
#else
#import "SecurityToolkit-Swift.h"
#endif

static NSString *const kRNSecErrorCode = @"RNSEC_NATIVE_ERROR";

@implementation SecurityToolkit {
  dispatch_queue_t _engineQueue;
}

- (instancetype)init
{
  if (self = [super init]) {
    // Detection reads the filesystem and process state; none of that belongs on
    // the JavaScript thread.
    _engineQueue = dispatch_queue_create("com.rnsecurity.engine", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)getEngineInfo:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  dispatch_async(_engineQueue, ^{
    @try {
      resolve([RNSecurityToolkitEngine engineInfoWithEngineVersion:@RNSEC_ENGINE_VERSION]);
    } @catch (NSException *exception) {
      reject(kRNSecErrorCode, exception.reason ?: exception.name, nil);
    }
  });
}

- (void)runCheck:(NSString *)checkId
         options:(NSDictionary *)options
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  NSDictionary *safeOptions = options ?: @{};

  dispatch_async(_engineQueue, ^{
    @try {
      resolve([RNSecurityToolkitEngine runCheck:checkId options:safeOptions]);
    } @catch (NSException *exception) {
      reject(kRNSecErrorCode, exception.reason ?: exception.name, nil);
    }
  });
}

- (void)runChecks:(NSArray *)checkIds
          options:(NSDictionary *)options
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  // Copy off the bridge values before hopping threads.
  NSMutableArray<NSString *> *ids = [NSMutableArray arrayWithCapacity:checkIds.count];
  for (id entry in checkIds) {
    if ([entry isKindOfClass:[NSString class]]) {
      [ids addObject:(NSString *)entry];
    }
  }
  NSDictionary *safeOptions = options ?: @{};

  dispatch_async(_engineQueue, ^{
    @try {
      resolve([RNSecurityToolkitEngine runChecks:ids options:safeOptions]);
    } @catch (NSException *exception) {
      reject(kRNSecErrorCode, exception.reason ?: exception.name, nil);
    }
  });
}

- (void)setScreenProtection:(BOOL)enabled
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject
{
  resolve(@([RNSecurityToolkitEngine setScreenProtection:enabled]));
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeSecurityToolkitSpecJSI>(params);
}

+ (NSString *)moduleName
{
  return @"SecurityToolkit";
}

@end
