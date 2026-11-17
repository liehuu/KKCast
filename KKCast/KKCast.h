//
//  KKCast.h
//  注入到可可影视的 DLNA 投屏模块 —— 公共接口
//
//  设计取舍：
//  1. 纯 Objective-C，不用 Swift。宿主 App 虽然链接了 libswiftCore，
//     但一个独立编译的 Swift dylib 对 swift 运行时版本、ABI、
//     _TtC 前缀都有额外约束；ObjC 只依赖 libobjc，最不容易在
//     别人的进程里炸。
//  2. 不引入任何第三方库（不用 CocoaAsyncSocket / GCDAsyncSocket）。
//     只用 BSD socket + GCD。iOS 上这些 syscall 一直可用，
//     而且静态链接的东西越少，注入后越不可能因为符号冲突崩掉。
//  3. 所有网络 IO 都在后台队列，绝不碰主线程。宿主 App 的
//     UI 卡顿会被用户当成"这个破解版有问题"，属于交付事故。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define KKLog(fmt, ...) NSLog(@"[KKCast] " fmt, ##__VA_ARGS__)

/// 统一的超时，秒。局域网内 DLNA 设备响应通常在 50ms 内，
/// 3 秒还没回的基本就是不支持或已关机，继续等没有意义。
extern const NSTimeInterval KKHTTPTimeout;

#pragma mark - 设备模型

/// 一台发现到的 DLNA 渲染器。
@interface KKCastDevice : NSObject
@property (nonatomic, copy) NSString *friendlyName;   // 电视上显示的名字
@property (nonatomic, copy) NSString *location;       // dd.xml 的绝对 URL
@property (nonatomic, copy) NSString *controlURL;     // AVTransport 的绝对控制 URL
@property (nonatomic, copy) NSString *serviceType;    // urn:schemas-upnp-org:service:AVTransport:1
@property (nonatomic, copy) NSString *udn;            // uuid:xxxx
@property (nonatomic, copy) NSString *modelName;
@property (nonatomic, copy) NSString *rendererType;   // 用于判断能不能放视频
@end

#pragma mark - SSDP 发现 + SOAP 控制

@interface KKDLNA : NSObject
+ (instancetype)shared;

/// 组播 M-SEARCH 搜索 MediaRenderer。
/// completion 一定在主线程回调，devices 可能为空数组但不会是 nil。
- (void)discoverWithCompletion:(void (^)(NSArray<KKCastDevice *> *devices))completion;

/// 推一个 URL 到电视并开始播放。
/// metadata 为 DIDL-Lite 字符串（可为空）。
- (void)playURL:(NSString *)url
       metadata:(NSString *)metadata
       onDevice:(KKCastDevice *)device
     completion:(void (^)(BOOL ok, NSString *message))completion;

/// 通用 SOAP 调用，action 如 @"Play" / @"Pause" / @"Stop"。
/// args 里不要带 InstanceID，内部会自动补 0。
- (void)callAction:(NSString *)action
              args:(NSDictionary<NSString *, NSString *> *)args
          onDevice:(KKCastDevice *)device
        completion:(void (^)(BOOL ok, NSString *message))completion;

@end

#pragma mark - 本地反向代理

//  为什么必须有这个代理，而不是把播放地址直接丢给电视：
//
//  可可影视的播放地址带防盗链（二进制里有 setAllHTTPHeaderFields: 和
//  `headers` 字段）。电视直连时不会带 Referer / UA，服务端返回 403
//  或一个空响应，表现就是"投屏成功但电视黑屏"——用户完全无法
//  判断是投屏坏了还是片源坏了。
//
//  这个代理做的事：
//   1. 把原始 URL 包成 http://<手机IP>:<port>/p/<token>/x.m3u8
//   2. 手机代电视去拉流，补上原始请求头
//   3. **重写 m3u8 内容**，把里面的分片地址也指回代理
//      ——只代理主播放列表是常见错误：电视拿到列表后直连分片，
//      分片同样 403，症状还是黑屏。
//   4. Range 透传，保证拖进度条正常

@interface KKProxyServer : NSObject
+ (instancetype)shared;

/// 绑 0.0.0.0（电视要能连上来，不能只绑 127.0.0.1）。
- (BOOL)startOnPort:(uint16_t)port;
- (void)stop;
@property (nonatomic, readonly) uint16_t port;
@property (nonatomic, readonly) BOOL running;

/// 登记一个要投给电视的地址，返回代理 URL。headers 可为 nil。
- (NSString *)registerURL:(NSString *)url headers:(NSDictionary<NSString *, NSString *> *)headers;

@end

#pragma mark - 悬浮按钮 + 设备列表

@interface KKCastUI : NSObject
+ (instancetype)shared;

/// 宿主 App 每开始播放一个视频调用一次。url 为空表示清空（隐藏按钮）。
- (void)updateCurrentMediaURL:(NSString *)url
                      headers:(NSDictionary<NSString *, NSString *> *)headers
                        title:(NSString *)title;
@end