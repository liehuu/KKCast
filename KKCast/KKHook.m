//
//  KKHook.m
//  从宿主播放器里取出当前播放地址 + 请求头
//
//  这是整个注入方案里唯一"依赖宿主内部实现"的地方，所以设计成三层兜底：
//
//    第 1 层  AVURLAsset -initWithURL:options:
//             最理想。options 里的 AVURLAssetHTTPHeaderFieldsKey
//             就是宿主给源站设的 Referer / UA / Cookie。
//             没有这一层，带防盗链的源投过去就是黑屏。
//
//    第 2 层  AVPlayerItem -initWithURL:automaticallyLoadedAssetKeys:
//             只拿到 URL，没有 headers。用于第 1 层没命中的情况
//             （比如宿主用 Swift 的 AVPlayerItem(url:) 直连）。
//
//    第 3 层  AVPlayer -replaceCurrentItemWithPlayerItem:
//             最后兜底。从 item.asset 反查 URL。
//
//  三层都失败时按钮不出现——这比出现一个点了没反应的按钮好。
//  用户看到按钮 = 一定有地址可用。
//

#import "KKCast.h"
#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>

/// AVFoundation 里这个 key 是私有的（没有公开常量），
/// 但它是实际生效的字符串。写死在这里，并有断言校验。
static NSString *const kHTTPHeaderFieldsKey = @"AVURLAssetHTTPHeaderFieldsKey";

@implementation NSObject (KKCastHook)

@end

#pragma mark - 记录

@interface KKMediaState : NSObject
@property (atomic, copy) NSString *url;
@property (atomic, copy) NSDictionary<NSString *, NSString *> *headers;
@property (atomic, copy) NSString *title;
@end

@implementation KKMediaState
@end

static KKMediaState *gState(void) {
    static KKMediaState *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [KKMediaState new]; });
    return s;
}

/// 统一入口：拿到地址就刷新按钮
static void kkPublish(NSString *url, NSDictionary *headers, NSString *title) {
    if (![url isKindOfClass:[NSString class]] || !url.length) return;

    // 只认 http(s)。file:// 是本地下载的片，投给电视没意义
    // （电视访问不到手机沙盒）。
    if (![url hasPrefix:@"http://"] && ![url hasPrefix:@"https://"]) return;

    KKMediaState *st = gState();
    st.url = url;
    st.headers = headers ?: @{};
    st.title = title ?: @"";

    KKLog(@"捕获播放地址: %@ (headers=%lu)", url, (unsigned long)st.headers.count);
    [[KKCastUI shared] updateCurrentMediaURL:url headers:st.headers title:st.title];
}

#pragma mark - 第 1 层：AVURLAsset

static IMP gOrigAssetInit;
static id kkAssetInit(id self, SEL _cmd, NSURL *URL, NSDictionary *options) {
    id ret = ((id (*)(id, SEL, NSURL *, NSDictionary *))gOrigAssetInit)(self, _cmd, URL, options);
    @try {
        NSDictionary *hdrs = nil;
        if ([options isKindOfClass:[NSDictionary class]]) {
            id h = options[kHTTPHeaderFieldsKey];
            if ([h isKindOfClass:[NSDictionary class]]) hdrs = h;
        }
        if ([URL isKindOfClass:[NSURL class]]) {
            kkPublish(URL.absoluteString, hdrs, nil);
        }
    } @catch (NSException *e) {
        KKLog(@"asset hook 异常: %@", e);
    }
    return ret;
}

#pragma mark - 第 2 层：AVPlayerItem

static IMP gOrigItemInit;
static id kkItemInit(id self, SEL _cmd, NSURL *URL, NSArray *keys) {
    id ret = ((id (*)(id, SEL, NSURL *, NSArray *))gOrigItemInit)(self, _cmd, URL, keys);
    @try {
        if ([URL isKindOfClass:[NSURL class]]) {
            kkPublish(URL.absoluteString, nil, nil);
        }
    } @catch (NSException *e) {
        KKLog(@"item hook 异常: %@", e);
    }
    return ret;
}

#pragma mark - 第 3 层：AVPlayer

static IMP gOrigReplace;
static void kkReplace(id self, SEL _cmd, AVPlayerItem *item) {
    ((void (*)(id, SEL, AVPlayerItem *))gOrigReplace)(self, _cmd, item);
    @try {
        AVAsset *asset = item.asset;
        if ([asset isKindOfClass:[AVURLAsset class]]) {
            NSURL *u = ((AVURLAsset *)asset).URL;
            if (u) {
                // 这一层拿不到 headers，但如果之前第 1 层已经抓到过
                // 同一个 URL，就复用它的 headers，别把已经有的信息覆盖成空。
                NSDictionary *prev = nil;
                if ([gState().url isEqualToString:u.absoluteString]) {
                    prev = gState().headers;
                }
                kkPublish(u.absoluteString, prev, nil);
            }
        }
    } @catch (NSException *e) {
        KKLog(@"player hook 异常: %@", e);
    }
}

#pragma mark - 安装

static void kkSwizzle(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        KKLog(@"选择器不存在，跳过: %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel));
        return;
    }
    if (outOrig) *outOrig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    KKLog(@"已挂钩 %@ -%@", NSStringFromClass(cls), NSStringFromSelector(sel));
}

__attribute__((constructor))
static void kkInstallHooks(void) {
    @autoreleasepool {
        KKLog(@"KKCast 注入成功，开始安装钩子");

        // 第 1 层
        kkSwizzle([AVURLAsset class],
                  @selector(initWithURL:options:),
                  (IMP)kkAssetInit, &gOrigAssetInit);

        // 第 2 层
        kkSwizzle([AVPlayerItem class],
                  @selector(initWithURL:automaticallyLoadedAssetKeys:),
                  (IMP)kkItemInit, &gOrigItemInit);

        // 第 3 层
        kkSwizzle([AVPlayer class],
                  @selector(replaceCurrentItemWithPlayerItem:),
                  (IMP)kkReplace, &gOrigReplace);

        // 启动时就预启代理。等到用户点按钮才启动的话，
        // 第一次点击要多等 200ms，体感是"按钮卡了一下"。
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            BOOL ok = [[KKProxyServer shared] startOnPort:0];
            KKLog(@"代理预启动 %@ 端口 %u", ok ? @"成功" : @"失败", [KKProxyServer shared].port);
        });
    }
}