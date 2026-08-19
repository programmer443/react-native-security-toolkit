#import <SecurityToolkitSpec/SecurityToolkitSpec.h>

/**
 * TurboModule adapter for the iOS security engine.
 *
 * This class exists only to satisfy the Codegen-generated protocol and to move
 * work off the JavaScript thread. The engine itself lives in Swift; see
 * `SecurityToolkitEngine.swift`.
 */
@interface SecurityToolkit : NSObject <NativeSecurityToolkitSpec>

@end
