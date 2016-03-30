//
//  FuckThisBlueDot.m
//  FuckThisBlueDot
//
//  Created by Timm Kandziora on 21.03.16.
//  Copyright © 2016 Timm Kandziora. All rights reserved.
//

#import <objc/runtime.h>
#import <Cocoa/Cocoa.h>

typedef void (*chimp)(id, SEL, ...);

@interface LPRunnable : NSObject
- (char)recentlyAdded;
@end

__attribute__((constructor))
static void init() {
    Class LPRunnable = objc_getClass("LPRunnable");
    // If anything is buggy, class_getInstanceMethod() may be initializing an object and causes unexpected behavior
    Method originalMethod = class_getInstanceMethod(LPRunnable, @selector(recentlyAdded));
    
    if (originalMethod != NULL) {
        //chimp originalImp = (chimp)class_getMethodImplementation(LPRunnable, @selector(recentlyAdded));
        
        IMP newImp = imp_implementationWithBlock(^(id _self, SEL _cmd) {
            return 0;
            
            //return originalImp(_self, @selector(recentlyAdded));
        });
        
        method_setImplementation(originalMethod, newImp);
    }
}
