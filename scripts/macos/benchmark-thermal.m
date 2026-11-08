// Read-only coarse system telemetry for the local complete-proof benchmark.
// Foundation maps unknown/unsupported thermal state to Nominal, and unknown/
// unsupported low-power status to NO. Neither value proves lack of throttling.
#import <Foundation/Foundation.h>
#include <stdio.h>

int main(void) {
    @autoreleasepool {
        NSProcessInfo *process = [NSProcessInfo processInfo];
        NSProcessInfoThermalState state = process.thermalState;
        NSString *name = @"unknown";
        switch (state) {
            case NSProcessInfoThermalStateNominal: name = @"nominal"; break;
            case NSProcessInfoThermalStateFair: name = @"fair"; break;
            case NSProcessInfoThermalStateSerious: name = @"serious"; break;
            case NSProcessInfoThermalStateCritical: name = @"critical"; break;
        }
        NSDictionary *record = @{
            @"schema_version": @1,
            @"thermal_state": @((NSInteger)state),
            @"thermal_state_name": name,
            @"low_power_mode_enabled": @(process.lowPowerModeEnabled),
            @"thermal_nominal_may_mean_unknown": @YES,
            @"low_power_false_may_mean_unknown": @YES
        };
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:&error];
        if (!json) {
            fprintf(stderr, "thermal telemetry JSON failed: %s\n", error.localizedDescription.UTF8String);
            return 1;
        }
        if (fwrite(json.bytes, 1, json.length, stdout) != json.length || fputc('\n', stdout) == EOF) {
            return 1;
        }
    }
    return 0;
}
