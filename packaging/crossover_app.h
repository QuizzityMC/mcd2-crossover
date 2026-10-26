// Discover by bundle identity, not the app's filename. Do not execute candidates.
static BOOL MCD2IsSupportedRuntimeIdentifier(NSString *identifier) {
    return [identifier isEqual:@"com.codeweavers.CrossOver"] || [identifier isEqual:@"com.franke.Whisky"] || [identifier isEqual:@"com.isaacmarovitz.Whisky"];
}
static NSString *MCD2RuntimeExecutableAtPath(NSString *path, NSString *identifier) {
    NSArray<NSString *> *relative = [identifier isEqual:@"com.codeweavers.CrossOver"] ?
        @[@"Contents/SharedSupport/CrossOver/bin/wine"] :
        @[@"Contents/SharedSupport/CrossOver/bin/wine",@"Contents/Resources/WhiskyCmd"];
    for (NSString *entry in relative) {
        NSString *candidate = [path stringByAppendingPathComponent:entry];
        if ([NSFileManager.defaultManager isExecutableFileAtPath:candidate]) return candidate;
    }
    return nil;
}
static NSString *MCD2CrossOverError(NSString *path) {
    if (!path.length) return @"CrossOver or Whisky was not found. Click Choose CrossOver and select your app.";
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[path stringByAppendingPathComponent:@"Contents/Info.plist"]];
    NSString *identifier = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class] ? info[@"CFBundleIdentifier"] : nil;
    if (!MCD2IsSupportedRuntimeIdentifier(identifier))
        return [NSString stringWithFormat:@"Cannot read a CrossOver or Whisky app at %@. Click Choose CrossOver to select it again.",path];
    if (!MCD2RuntimeExecutableAtPath(path,identifier))
        return @"The selected app is missing its runtime executable. Choose another app.";
    return nil;
}
static NSString *MCD2FindCrossOver(NSString *supportPath) {
    NSData *data = [NSData dataWithContentsOfFile:[supportPath stringByAppendingPathComponent:@"crossover-app.json"]];
    if (data) {
        id saved = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if ([saved isKindOfClass:NSDictionary.class] && [saved[@"path"] isKindOfClass:NSString.class]) return saved[@"path"];
        return nil;
    }
    for (NSString *folder in @[@"/Applications",[NSHomeDirectory() stringByAppendingPathComponent:@"Applications"]]) {
        NSMutableArray *names = [NSMutableArray arrayWithArray:@[@"CrossOver.app",@"Whisky.app"]];
        [names addObjectsFromArray:[[NSFileManager.defaultManager contentsOfDirectoryAtPath:folder error:nil] sortedArrayUsingSelector:@selector(localizedStandardCompare:)] ?: @[]];
        for (NSString *name in names) {
            if (![name.pathExtension.lowercaseString isEqual:@"app"]) continue;
            NSString *path = [folder stringByAppendingPathComponent:name];
            if (!MCD2CrossOverError(path)) return path;
        }
    }
    NSURL *registered = [NSWorkspace.sharedWorkspace URLForApplicationWithBundleIdentifier:@"com.codeweavers.CrossOver"];
    if (registered && !MCD2CrossOverError(registered.path)) return registered.path;
    for (NSString *identifier in @[@"com.franke.Whisky",@"com.isaacmarovitz.Whisky"]) {
        NSURL *candidate = [NSWorkspace.sharedWorkspace URLForApplicationWithBundleIdentifier:identifier];
        if (candidate && !MCD2CrossOverError(candidate.path)) return candidate.path;
    }
    return nil;
}
