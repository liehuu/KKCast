//
//  KKDLNA.m
//  SSDP 发现 + SOAP 控制
//
//  关键设计：只发 M-SEARCH（单播收响应），**不加入组播组**。
//  在 iOS 上 IP_ADD_MEMBERSHIP 需要 com.apple.developer.networking.multicast
//  这个受管 entitlement，普通重签拿不到。而 M-SEARCH 只是往
//  239.255.255.250:1900 发一个 UDP 包，响应是单播回来的，
//  整条路径不需要 entitlement，只需要"本地网络"权限。
//  代价是收不到设备主动发的 NOTIFY，但投屏场景是用户点按钮才搜，
//  本来就不需要被动监听。
//

#import "KKCast.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <sys/select.h>

const NSTimeInterval KKHTTPTimeout = 3.0;
static NSString *const kSSDPHost = @"239.255.255.250";
static const uint16_t kSSDPPort = 1900;
static NSString *const kAVT = @"urn:schemas-upnp-org:service:AVTransport:1";

#pragma mark - 设备

@implementation KKCastDevice
- (NSString *)description {
    return [NSString stringWithFormat:@"<Device %@ @ %@>", self.friendlyName, self.location];
}
@end

#pragma mark - 证书

/// 只对 DD.xml 拉取放行自签证书。
/// 注意：**代理层不能用这个**——代理转发的是用户真实流量，
/// 无条件信任任何证书等于自己给中间人开门。所以这里只给发现层用。
@interface KKTrustAllDelegate : NSObject <NSURLSessionDelegate>
+ (instancetype)shared;
@end

@implementation KKTrustAllDelegate
+ (instancetype)shared {
    static KKTrustAllDelegate *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [KKTrustAllDelegate new]; });
    return s;
}
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod
         isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}
@end

#pragma mark - dd.xml 解析

/// 只关心 AVTransport 服务的 controlURL。
/// 用 NSXMLParser 而不是正则：dd.xml 里 controlURL 是相对路径，
/// 而且不同厂商的 namespace 前缀五花八门（有的用 s:, 有的用 ns0:），
/// 按标签名匹配前缀是最脆的写法。
@interface KKServiceParser : NSObject <NSXMLParserDelegate>
@property (nonatomic, copy) NSString *controlURL;
@property (nonatomic, copy) NSString *serviceType;
@property (nonatomic, copy) NSString *friendlyName;
@property (nonatomic, copy) NSString *modelName;
@property (nonatomic, copy) NSString *deviceType;
@end

@implementation KKServiceParser {
    NSMutableString *_buf;
    NSString *_curElement;
    BOOL _inService;
    // 当前这个 service 块内部累积的值
    NSString *_curServiceType;
    NSString *_curControlURL;
}

- (instancetype)init {
    if ((self = [super init])) {
        _buf = [NSMutableString string];
    }
    return self;
}

- (void)parser:(NSXMLParser *)parser
didStartElement:(NSString *)elementName
  namespaceURI:(NSString *)namespaceURI
 qualifiedName:(NSString *)qName
    attributes:(NSDictionary *)attributeDict {
    // 去掉 namespace 前缀，只留本地名
    NSString *name = elementName;
    NSRange colon = [name rangeOfString:@":"];
    if (colon.location != NSNotFound) {
        name = [name substringFromIndex:colon.location + 1];
    }
    _curElement = name;
    [_buf setString:@""];

    if ([name isEqualToString:@"service"]) {
        _inService = YES;
        _curServiceType = nil;
        _curControlURL = nil;
    }
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string {
    if (string) [_buf appendString:string];
}

- (void)parser:(NSXMLParser *)parser
 didEndElement:(NSString *)elementName
  namespaceURI:(NSString *)namespaceURI
 qualifiedName:(NSString *)qName {
    NSString *name = elementName;
    NSRange colon = [name rangeOfString:@":"];
    if (colon.location != NSNotFound) {
        name = [name substringFromIndex:colon.location + 1];
    }
    NSString *text = [_buf stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if (_inService) {
        if ([name isEqualToString:@"serviceType"]) {
            _curServiceType = [text copy];
        } else if ([name isEqualToString:@"controlURL"]) {
            _curControlURL = [text copy];
        } else if ([name isEqualToString:@"service"]) {
            // 只采纳 AVTransport 这一块。
            //
            // 这里必须用"块内局部变量 + 采纳后写进最终属性"的写法。
            // 早先直接在解析过程中往 self.serviceType 里写，遇到
            // AVTransport 排在 RenderingControl 前面（dd.xml 的服务顺序
            // 各厂商不统一）时，后面的 RenderingControl 会把已经采纳的
            // AVTransport 覆盖成 nil —— 表现是"这台电视明明支持却搜不到"，
            // 而且换一台电视就好了，极难定位。
            if (_curServiceType.length && _curControlURL.length &&
                [_curServiceType containsString:@"AVTransport"] &&
                !_controlURL.length) {          // 已采纳过就不再覆盖
                _serviceType = [_curServiceType copy];
                _controlURL = [_curControlURL copy];
            }
            _curServiceType = nil;
            _curControlURL = nil;
            _inService = NO;
        }
        return;
    }

    if ([name isEqualToString:@"friendlyName"] && !_friendlyName.length) {
        _friendlyName = [text copy];
    } else if ([name isEqualToString:@"modelName"] && !_modelName.length) {
        _modelName = [text copy];
    } else if ([name isEqualToString:@"deviceType"] && !_deviceType.length) {
        _deviceType = [text copy];
    }
}

@end

#pragma mark - DLNA

@interface KKDLNA ()
@property (nonatomic, strong) NSURLSession *session;
@end

/// 私有方法显式声明，避免调用点早于定义时触发
/// -Wobjc-method-access（-Werror 下等于编译失败）。
@interface KKDLNA (Private)
- (NSArray<NSString *> *)ssdpSearch;
- (NSDictionary<NSString *, NSString *> *)parseHeaders:(NSString *)raw;
- (void)resolveLocation:(NSString *)location completion:(void (^)(KKCastDevice *))completion;
- (NSString *)xmlEscape:(NSString *)s;
@end

@implementation KKDLNA

+ (instancetype)shared {
    static KKDLNA *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [KKDLNA new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        c.timeoutIntervalForRequest = KKHTTPTimeout;
        c.timeoutIntervalForResource = 30;
        c.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        // 有些电视/盒子 dd.xml 里的 Location 是 https 且证书自签。
        // 用一个不校验的 delegate，避免整条发现链因为证书失败。
        _session = [NSURLSession sessionWithConfiguration:c
                                                 delegate:[KKTrustAllDelegate shared]
                                            delegateQueue:nil];
    }
    return self;
}

#pragma mark SSDP

- (void)discoverWithCompletion:(void (^)(NSArray<KKCastDevice *> *))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<NSString *> *locations = [self ssdpSearch];

        if (locations.count == 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(@[]);
            });
            return;
        }

        dispatch_group_t group = dispatch_group_create();
        NSMutableArray *devices = [NSMutableArray array];
        NSLock *lock = [NSLock new];

        for (NSString *loc in locations) {
            dispatch_group_enter(group);
            [self resolveLocation:loc completion:^(KKCastDevice *dev) {
                if (dev) {
                    [lock lock];
                    BOOL dup = NO;
                    for (KKCastDevice *d in devices) {
                        if ([d.location isEqualToString:dev.location]) { dup = YES; break; }
                    }
                    if (!dup) [devices addObject:dev];
                    [lock unlock];
                }
                dispatch_group_leave(group);
            }];
        }

        dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)));

        // 按名字排序，用户在一堆 "客厅电视" 里找起来容易些
        [devices sortUsingComparator:^NSComparisonResult(KKCastDevice *a, KKCastDevice *b) {
            return [a.friendlyName localizedCaseInsensitiveCompare:b.friendlyName];
        }];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(devices);
        });
    });
}

/// 返回去重后的 LOCATION 列表。
- (NSArray<NSString *> *)ssdpSearch {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        KKLog(@"socket() 失败 errno=%d", errno);
        return @[];
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(kSSDPPort);
    inet_pton(AF_INET, kSSDPHost.UTF8String, &dst.sin_addr);

    const char *msg =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
        "\r\n";

    // 发三次。UDP 会丢包，单发一次在多设备/弱 WiFi 下漏设备的概率不低。
    // 间隔与 MX=2 的 2 秒上限配合：设备随机延迟回应，分批发能覆盖更长窗口。
    for (int i = 0; i < 3; i++) {
        ssize_t n = sendto(fd, msg, strlen(msg), 0,
                           (struct sockaddr *)&dst, sizeof(dst));
        if (n < 0) KKLog(@"sendto 失败 errno=%d", errno);
        usleep(250 * 1000);
    }

    NSMutableArray *locations = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];

    // 收集窗口 2.5s：MX=2 意味着设备最晚 2s 回应，留 0.5s 余量
    NSTimeInterval deadline = [[NSDate date] timeIntervalSince1970] + 2.5;

    while ([[NSDate date] timeIntervalSince1970] < deadline) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;

        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0) continue;

        char buf[4096];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n <= 0) continue;
        buf[n] = '\0';

        NSString *resp = [NSString stringWithUTF8String:buf];
        if (!resp) continue;

        NSDictionary *hdrs = [self parseHeaders:resp];
        NSString *loc = hdrs[@"location"];
        if (!loc.length) continue;

        // ST 是设备回的"我是什么"。我们只搜了 MediaRenderer，
        // 但有些设备回 upnp:rootdevice，也要收——它照样能渲染。
        NSString *st = [hdrs[@"st"] lowercaseString] ?: @"";
        if (st.length &&
            ![st containsString:@"mediarenderer"] &&
            ![st containsString:@"mediaserver"] &&
            ![st isEqualToString:@"upnp:rootdevice"]) {
            continue;
        }

        if ([seen containsObject:loc]) continue;
        [seen addObject:loc];
        [locations addObject:loc];
    }

    close(fd);
    KKLog(@"SSDP：%lu 个候选", (unsigned long)locations.count);
    return locations;
}

/// 把 SSDP / HTTP 响应头解析成小写 key 的字典。
/// 头名大小写不统一是常态（LOCATION / Location / location 都见过）。
- (NSDictionary<NSString *, NSString *> *)parseHeaders:(NSString *)raw {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    NSArray *lines = [raw componentsSeparatedByString:@"\r\n"];
    if (lines.count < 2) lines = [raw componentsSeparatedByString:@"\n"];
    for (NSString *line in lines) {
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        NSString *k = [[line substringToIndex:colon.location]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]
                       .lowercaseString;
        NSString *v = [[line substringFromIndex:colon.location + 1]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (k.length && v.length) d[k] = v;
    }
    return d;
}

#pragma mark dd.xml

- (void)resolveLocation:(NSString *)location completion:(void (^)(KKCastDevice *))completion {
    NSURL *url = [NSURL URLWithString:location];
    if (!url) { completion(nil); return; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = KKHTTPTimeout;
    req.HTTPMethod = @"GET";

    [[_session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (!data.length) {
            KKLog(@"dd.xml 拉取失败 %@ : %@", location, err.localizedDescription);
            completion(nil);
            return;
        }

        KKServiceParser *p = [KKServiceParser new];
        NSXMLParser *xp = [[NSXMLParser alloc] initWithData:data];
        xp.delegate = p;
        [xp parse];

        if (!p.controlURL.length) {
            KKLog(@"dd.xml 里没有 AVTransport：%@", location);
            completion(nil);
            return;
        }

        // controlURL 几乎总是相对路径（/upnp/control/AVTransport1），
        // 少数设备给绝对 URL。用 relativeToURL 一次搞定两种情况。
        NSURL *ctrl = [NSURL URLWithString:p.controlURL relativeToURL:url];

        KKCastDevice *dev = [KKCastDevice new];
        dev.location = location;
        dev.controlURL = ctrl.absoluteString;
        dev.serviceType = p.serviceType ?: kAVT;
        dev.friendlyName = p.friendlyName.length ? p.friendlyName : url.host;
        dev.modelName = p.modelName ?: @"";
        dev.rendererType = p.deviceType ?: @"";
        dev.udn = @"";
        completion(dev);
    }] resume];
}

#pragma mark SOAP

- (NSString *)xmlEscape:(NSString *)s {
    if (!s) return @"";
    NSMutableString *m = [s mutableCopy];
    [m replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@">" withString:@"&gt;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"\"" withString:@"&quot;" options:0 range:NSMakeRange(0, m.length)];
    [m replaceOccurrencesOfString:@"'" withString:@"&apos;" options:0 range:NSMakeRange(0, m.length)];
    return m;
}

- (void)playURL:(NSString *)url
       metadata:(NSString *)metadata
       onDevice:(KKCastDevice *)device
     completion:(void (^)(BOOL, NSString *))completion {
    NSDictionary *args = @{
        @"CurrentURI": url ?: @"",
        @"CurrentURIMetaData": metadata ?: @""
    };
    [self callAction:@"SetAVTransportURI" args:args onDevice:device completion:^(BOOL ok, NSString *msg) {
        if (!ok) {
            if (completion) completion(NO, msg);
            return;
        }
        // 设完地址立刻播。有的设备需要几十毫秒缓冲，重试一次更稳。
        [self callAction:@"Play" args:@{@"Speed": @"1"} onDevice:device
              completion:^(BOOL ok2, NSString *msg2) {
            if (ok2) {
                if (completion) completion(YES, @"已开始播放");
            } else {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                               dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    [self callAction:@"Play" args:@{@"Speed": @"1"} onDevice:device
                          completion:^(BOOL ok3, NSString *msg3) {
                        if (completion) completion(ok3, ok3 ? @"已开始播放" : msg3);
                    }];
                });
            }
        }];
    }];
}

- (void)callAction:(NSString *)action
              args:(NSDictionary<NSString *, NSString *> *)args
          onDevice:(KKCastDevice *)device
        completion:(void (^)(BOOL, NSString *))completion {
    if (!device.controlURL.length) {
        if (completion) completion(NO, @"设备地址无效");
        return;
    }

    NSMutableString *body = [NSMutableString string];
    [body appendString:@"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"];
    [body appendString:@"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                      @"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"];
    [body appendString:@"<s:Body>"];
    [body appendFormat:@"<u:%@ xmlns:u=\"%@\">", action, device.serviceType ?: kAVT];
    // InstanceID 永远先写。顺序在 SOAP 里不重要，但有些廉价固件
    // 的实现按顺序取字段，放第一个最保险。
    [body appendString:@"<InstanceID>0</InstanceID>"];
    for (NSString *k in args) {
        [body appendFormat:@"<%@>%@</%@>", k, [self xmlEscape:args[k]], k];
    }
    [body appendFormat:@"</u:%@>", action];
    [body appendString:@"</s:Body></s:Envelope>"];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:device.controlURL]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = KKHTTPTimeout;
    [req setValue:[NSString stringWithFormat:@"\"%@#%@\"", device.serviceType ?: kAVT, action]
        forHTTPHeaderField:@"SOAPAction"];
    [req setValue:@"text/xml; charset=\"utf-8\"" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[_session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
        if (err) {
            KKLog(@"%@ 失败：%@", action, err.localizedDescription);
            if (completion) completion(NO, err.localizedDescription);
            return;
        }
        if (code >= 200 && code < 300) {
            if (completion) completion(YES, nil);
            return;
        }
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        // UPnP 的错误会带 <errorCode>，捞出来比让用户看 500 有用
        NSString *code2 = @"";
        NSRange r1 = [text rangeOfString:@"<errorCode>"];
        if (r1.location != NSNotFound) {
            NSRange r2 = [text rangeOfString:@"</errorCode>"];
            if (r2.location != NSNotFound && r2.location > r1.location + 11) {
                code2 = [text substringWithRange:NSMakeRange(r1.location + 11, r2.location - r1.location - 11)];
            }
        }
        KKLog(@"%@ HTTP %ld %@", action, (long)code, text);
        if (completion) {
            completion(NO, code2.length ? [NSString stringWithFormat:@"电视返回错误 %@", code2]
                                        : [NSString stringWithFormat:@"电视返回 %ld", (long)code]);
        }
    }] resume];
}

@end