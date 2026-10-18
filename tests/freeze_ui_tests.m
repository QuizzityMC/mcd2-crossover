// Exercise the real AppKit capture action with controlled helper responses.
#define main mcd2_production_main
#import "../packaging/installer.m"
#undef main
@implementation CrossoverUpdater
+ (instancetype)shared { static CrossoverUpdater *u; if (!u) u=[self new]; return u; }
- (void)startWithBusyCheck:(BOOL (^)(void))check {}
- (void)addItemsToMenu:(NSMenu *)menu {}
- (BOOL)allowsNewOperation { return YES; }
- (BOOL)mustWaitBeforeQuitting { return NO; }
@end
@interface FreezeTestApp : MCD2App
@property NSDictionary *reply;
@property NSInteger calls;
@property NSInteger error;
@end
@implementation FreezeTestApp
- (void)refreshAccount {}
- (void)reportError:(NSInteger)code exit:(NSNumber *)exitCode system:(NSNumber *)system local:(NSString *)local { self.error=code; }
- (void)openTroubleshooting:(id)sender { self.diagnosticPanel=[NSPanel new]; self.recordStatus=[NSTextField labelWithString:@""];self.saveLogsButton=[NSButton new];self.recordButton=[NSButton new]; }
- (void)diagnostics:(NSString *)command output:(NSString *)path completion:(void (^)(NSDictionary *, BOOL))completion {
 NSAssert([command isEqual:@"capture"],@"capture action must request capture");self.calls++;completion(self.reply,YES);
}
@end
static void check(BOOL ok,const char *message) { if(!ok){fprintf(stderr,"FAIL: %s\n",message);exit(1);} printf("PASS: %s\n",message); }
int main(void) { @autoreleasepool {
 [NSApplication sharedApplication];
 FreezeTestApp *a=[FreezeTestApp new];a.reply=@{@"capture_outcome":@"captured",@"available":@YES};
 [a captureFreeze:nil];check(a.calls==1 && a.diagnosticPanel!=nil,"menu capture opens panel and starts once");
 check([a.recordStatus.stringValue containsString:@"captured"] && a.saveLogsButton.enabled,"successful sample can be exported");
 [a updateRecording:@{@"active":@NO}];check([a.recordStatus.stringValue containsString:@"captured"],"status refresh preserves capture result");
 a.diagnosticsBusy=YES;[a captureFreeze:nil];check(a.calls==1,"duplicate clicks do not launch another sample");a.diagnosticsBusy=NO;
 NSArray *outcomes=@[@"game_not_running",@"ambiguous_game",@"process_changed",@"sample_timeout",@"sample_denied",@"sample_empty",@"sample_failed",@"sample_missing",@"settings_missing"];
 NSArray *codes=@[@5003,@5004,@5004,@5005,@5005,@5005,@5005,@5005,@5005];
 for(NSUInteger i=0;i<outcomes.count;i++){a.reply=@{@"capture_outcome":outcomes[i],@"available":@YES};[a captureFreeze:nil];check(a.error==[codes[i] integerValue] && a.saveLogsButton.enabled,"capture failure displays the matching error and permits export");}
 a.reply=@{@"capture_outcome":@"sample_timeout",@"available":@YES};[a captureFreeze:nil];
 check([a.recordStatus.stringValue containsString:@"60 seconds"],"timeout reason is visible without opening exported logs");
 a.reply=@{@"capture_outcome":@"sample_denied",@"available":@YES};[a captureFreeze:nil];
 check([a.recordStatus.stringValue containsString:@"denied access"],"permission failure is distinguished from an empty report");
 a.reply=@{@"capture_outcome":@"captured",@"truncated":@YES,@"available":@YES};[a captureFreeze:nil];
 check([a.recordStatus.stringValue containsString:@"omitted"],"partial capture is explicitly labelled");
 } return 0; }
