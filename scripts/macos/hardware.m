#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

// Runtime observations, not inferred capabilities or a proving-mode claim.
int main(void) {
    @autoreleasepool {
        NSMutableArray *devices = [NSMutableArray array];
        for (id<MTLDevice> device in MTLCopyAllDevices()) {
            NSMutableArray *families = [NSMutableArray array];
            for (NSUInteger family = MTLGPUFamilyApple1; family <= MTLGPUFamilyApple10; ++family) {
                if ([device supportsFamily:(MTLGPUFamily)family]) {
                    [families addObject:@(family)];
                }
            }
            for (NSNumber *family in @[@(MTLGPUFamilyMac2), @(MTLGPUFamilyMetal3), @(MTLGPUFamilyMetal4)]) {
                if ([device supportsFamily:(MTLGPUFamily)family.unsignedIntegerValue]) {
                    [families addObject:family];
                }
            }
            [devices addObject:@{
                @"name": device.name,
                @"unified_memory": @(device.hasUnifiedMemory),
                @"recommended_max_working_set_bytes": @(device.recommendedMaxWorkingSetSize),
                @"max_buffer_bytes": @(device.maxBufferLength),
                @"currently_allocated_bytes": @(device.currentAllocatedSize),
                @"supported_family_ids": families
            }];
        }
        NSProcessInfo *info = NSProcessInfo.processInfo;
        NSDictionary *report = @{
            @"physical_memory_bytes": @(info.physicalMemory),
            @"logical_cpus": @(info.processorCount),
            @"active_cpus": @(info.activeProcessorCount),
            @"metal_devices": devices
        };
        NSError *error = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];
        if (!data) { fprintf(stderr, "%s\n", error.description.UTF8String); return 1; }
        fwrite(data.bytes, 1, data.length, stdout);
        putchar('\n');
        return devices.count ? 0 : 2;
    }
}
