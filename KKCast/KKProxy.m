//
//  KKProxy.m
//  本地反向代理：给电视一个能播的地址
//
//  三个必须做对的地方（做错任何一个都是"投屏成功但电视黑屏"）：
//   1. 主播放列表要重写：m3u8 里的分片/子列表是相对地址，
//      电视会按"播放列表所在 host"去拼。我们只代理列表不代理分片，
//      电视就去直连分片原站，照样 403。
//   2. Range 必须透传：拖进度条时电视会发 Range 请求，
//      不透传就只能从头播。
//   3. Host / 鉴权头不能带出去：源站可能按 Host 校验。
//

#import "KKCast.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <ifaddrs.h>
#import <sys/select.h>

/// 内存里最多缓存多大的上游响应。超过这个就走落盘 + 流式发送。
/// 48MB 是权衡：ts 分片通常 1-5MB，远低于它；mp4 整片可能几百 MB，
/// 一次性读进内存会在这台手机上直接 OOM 被系统杀掉。
static const NSUInteger kInlineMaxBytes = 48 * 1024 * 1024;

/// 一条登记记录：代理 URL 里的 token → 真实地址 + 请求头
@interface KKProxyEntry : NSObject
@property (nonatomic, copy) NSString *url;
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *headers;
@property (nonatomic, copy) NSString *title;
@end
@implementation KKProxyEntry
@end

@class KKProxyStreamer;

@interface KKProxyServer ()
@property (nonatomic, assign) int listenFD;
@property (nonatomic, assign) uint16_t port;
@property (nonatomic, assign) BOOL running;
@property (nonatomic, strong) NSMutableDictionary<NSString *, KKProxyEntry *> *entries;
@property (nonatomic, strong) NSLock *lock;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSMutableSet<NSString *> *hopHeaders;
/// 持有进行中的流，避免被提前释放导致连接悬空
@property (nonatomic, strong) NSMutableSet<KKProxyStreamer *> *streamers;
@end

/// 内部/给 streamer 用的接口。放在这里是为了让编译器在
/// streamer 的实现里能看到这些方法签名，不然会有
/// "no visible @interface declares the selector" 警告，
/// 而这类警告在 -Werror 的 CI 上等于编译失败。
@interface KKProxyServer (Internal)
- (void)sendStreamHeader:(int)client
                    code:(NSInteger)code
                    type:(NSString *)type
                  length:(NSUInteger)length
                   extra:(NSDictionary<NSString *, NSString *> *)extra;
- (void)sendWholeResponse:(int)client
                     code:(NSInteger)code
                     type:(NSString *)type
                     body:(NSData *)body;
- (NSString *)tokenForEntryByAddress:(NSString *)address;
- (NSString *)rewritePlaylist:(NSString *)text
                      baseURL:(NSString *)baseURL
                        token:(NSString *)token
                         port:(uint16_t)port;
- (void)removeStreamer:(KKProxyStreamer *)s;
@end

/// 流式转发一个上游响应到 client socket。
///
/// 为什么不用 dataTaskWithRequest 的 completionHandler：
/// 那个 API 会把整个响应体读进内存。整片 mp4 常见 200MB～2GB，
/// 在手机上直接 OOM 被系统杀掉——用户看到的是"一投屏就闪退"，
/// 而日志里没有任何我们的错误（是系统杀的，我们没法记录）。
/// 流式转发是来一块转一块，内存占用只跟块大小有关。
@interface KKProxyStreamer : NSObject <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, assign) int client;
@property (nonatomic, weak) KKProxyServer *owner;
@property (nonatomic, copy) NSString *target;
@property (nonatomic, assign) BOOL headerSent;
@property (nonatomic, assign) BOOL playlistMode;
@property (nonatomic, strong) NSMutableData *playlistBuf;
- (instancetype)initWithRequest:(NSURLRequest *)req
                         client:(int)client
                          owner:(KKProxyServer *)owner
                         target:(NSString *)target;
- (void)begin;
- (void)finish;
- (void)flushPlaylistWithCode:(NSInteger)code;
@end

@implementation KKProxyServer

+ (instancetype)shared {
    static KKProxyServer *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [KKProxyServer new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _entries = [NSMutableDictionary dictionary];
        _lock = [NSLock new];
        _streamers = [NSMutableSet set];
        // 这些头逐跳有效，代理转发时必须删掉，否则源站会当成协议错
        _hopHeaders = [NSMutableSet setWithArray:@[
            @"connection", @"keep-alive", @"proxy-authenticate",
            @"proxy-authorization", @"te", @"trailer",
            @"transfer-encoding", @"upgrade", @"host"
        ]];

        NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        c.timeoutIntervalForRequest = 15;
        c.timeoutIntervalForResource = 60;
        c.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        c.HTTPMaximumConnectionsPerHost = 8;
        _session = [NSURLSession sessionWithConfiguration:c];
    }
    return self;
}

- (BOOL)startOnPort:(uint16_t)port {
    if (_running) return YES;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { KKLog(@"proxy socket 失败 errno=%d", errno); return NO; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // 绑 INADDR_ANY：电视要连手机，绑 127.0.0.1 就只有本机能访问
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        KKLog(@"proxy bind %u 失败 errno=%d", port, errno);
        close(fd);
        return NO;
    }
    if (listen(fd, 16) < 0) {
        KKLog(@"proxy listen 失败 errno=%d", errno);
        close(fd);
        return NO;
    }

    // 如果传 0，让内核分配端口，再读回来
    if (port == 0) {
        struct sockaddr_in bound;
        socklen_t len = sizeof(bound);
        getsockname(fd, (struct sockaddr *)&bound, &len);
        port = ntohs(bound.sin_port);
    }

    _listenFD = fd;
    _port = port;
    _running = YES;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self acceptLoop];
    });

    KKLog(@"proxy 已启动 0.0.0.0:%u", port);
    return YES;
}

- (void)stop {
    if (!_running) return;
    _running = NO;
    if (_listenFD > 0) {
        shutdown(_listenFD, SHUT_RDWR);
        close(_listenFD);
        _listenFD = -1;
    }
}

- (void)acceptLoop {
    while (_running) {
        int fd = _listenFD;
        if (fd <= 0) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {1, 0};
        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0) continue;

        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int client = accept(fd, (struct sockaddr *)&cli, &clen);
        if (client < 0) continue;

        // 每个连接一条串行队列，避免同一连接的请求乱序
        dispatch_queue_t q = dispatch_queue_create("kkcast.proxy.conn", DISPATCH_QUEUE_SERIAL);
        dispatch_async(q, ^{
            @autoreleasepool {
                [self handleClient:client];
            }
        });
    }
}

#pragma mark - 注册

- (NSString *)registerURL:(NSString *)url
                  headers:(NSDictionary<NSString *, NSString *> *)headers {
    if (!url.length) return nil;

    NSString *token = [[NSUUID UUID] UUIDString].lowercaseString;
    token = [token stringByReplacingOccurrencesOfString:@"-" withString:@""];

    KKProxyEntry *e = [KKProxyEntry new];
    e.url = url;
    e.headers = headers ?: @{};
    e.title = @"";

    [_lock lock];
    _entries[token] = e;
    // 别无限涨：保留最近 64 条就够用户切集用了
    if (_entries.count > 64) {
        NSArray *keys = [_entries allKeys];
        for (NSUInteger i = 0; i < keys.count - 64; i++) {
            [_entries removeObjectForKey:keys[i]];
        }
    }
    [_lock unlock];

    NSString *ip = [self localIPAddress];
    NSString *ext = [self guessExtension:url];
    return [NSString stringWithFormat:@"http://%@:%u/p/%@/x.%@", ip, _port, token, ext];
}

/// 猜扩展名。有些电视按后缀选解码器，写成 .m3u8 / .mp4 比乱写更稳。
- (NSString *)guessExtension:(NSString *)url {
    NSString *path = [NSURL URLWithString:url].path.lowercaseString ?: @"";
    if ([path hasSuffix:@".m3u8"]) return @"m3u8";
    if ([path hasSuffix:@".mp4"]) return @"mp4";
    if ([path hasSuffix:@".ts"]) return @"ts";
    if ([path hasSuffix:@".mkv"]) return @"mkv";
    if ([path hasSuffix:@".flv"]) return @"flv";
    return @"m3u8";
}

/// 拿本机在局域网里的地址。en0 通常是 WiFi。
/// 不能用 127.0.0.1——那是手机自己，电视连不上。
- (NSString *)localIPAddress {
    NSString *ip = nil;
    struct ifaddrs *addrs = NULL;
    if (getifaddrs(&addrs) == 0) {
        for (struct ifaddrs *p = addrs; p != NULL; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            NSString *name = [NSString stringWithUTF8String:p->ifa_name];
            if (![name hasPrefix:@"en"] && ![name hasPrefix:@"bridge"]) continue;
            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            NSString *cand = [NSString stringWithUTF8String:buf];
            if ([cand hasPrefix:@"169.254."]) continue;   // 自动私有地址，无效
            if ([cand isEqualToString:@"127.0.0.1"]) continue;
            ip = cand;
            break;
        }
        freeifaddrs(addrs);
    }
    return ip ?: @"127.0.0.1";
}

#pragma mark - 处理连接

- (void)handleClient:(int)client {
    @autoreleasepool {
        // 读请求头。DLNA 电视的请求头很小，4KB 足够；
        // 但为了容错读到 8KB。
        NSMutableData *head = [NSMutableData data];
        char buf[2048];
        while (head.length < 8192) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            [head appendBytes:buf length:n];
            NSData *sep = [@"\r\n\r\n" dataUsingEncoding:NSASCIIStringEncoding];
            if ([head rangeOfData:sep options:0 range:NSMakeRange(0, head.length)].location != NSNotFound) {
                break;
            }
        }
        if (!head.length) { close(client); return; }

        NSString *raw = [[NSString alloc] initWithData:head encoding:NSUTF8StringEncoding];
        if (!raw) raw = [[NSString alloc] initWithData:head encoding:NSISOLatin1StringEncoding];
        if (!raw) { close(client); return; }

        NSArray *lines = [raw componentsSeparatedByString:@"\r\n"];
        if (lines.count == 0) { close(client); return; }

        NSArray *reqParts = [lines[0] componentsSeparatedByString:@" "];
        if (reqParts.count < 2) { [self respond:client code:400 text:@"bad request"]; return; }

        NSString *method = reqParts[0];
        NSString *path = reqParts[1];

        // 解析请求头
        NSMutableDictionary *reqHeaders = [NSMutableDictionary dictionary];
        for (NSUInteger i = 1; i < lines.count; i++) {
            NSString *line = lines[i];
            NSRange c = [line rangeOfString:@":"];
            if (c.location == NSNotFound) continue;
            NSString *k = [[line substringToIndex:c.location] lowercaseString];
            NSString *v = [[line substringFromIndex:c.location + 1]
                           stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (k.length) reqHeaders[k] = v;
        }

        // 路径形态两种：
        //   /p/<token>/x.m3u8              → 用登记表里的原始地址（入口）
        //   /p/<token>/<转义的绝对URL>      → 用路径里的地址（重写后的分片/子列表）
        //
        // 第二种是重写播放列表时产生的。早先的写法只认 token、
        // 一律回原始地址，结果每个分片请求都返回主列表本身，
        // 电视拿到一堆 #EXTM3U 当分片解码，必然黑屏。
        NSArray *segs = [path componentsSeparatedByString:@"/"];
        NSString *token = nil;
        if (segs.count >= 3 && [segs[1] isEqualToString:@"p"]) {
            token = segs[2];
        }
        if (!token.length) { [self respond:client code:404 text:@"not found"]; return; }

        [_lock lock];
        KKProxyEntry *entry = _entries[token];
        [_lock unlock];
        if (!entry) { [self respond:client code:404 text:@"token expired"]; return; }

        // 取出 token 之后的部分。因为编码时把 / 转成了 %2F，
        // 这里 componentsSeparatedByString 不会把它切开，
        // 拿最后一段再解转义就是完整 URL。
        NSString *target = entry.url;
        if (segs.count >= 4) {
            NSMutableArray *tail = [NSMutableArray array];
            for (NSUInteger i = 3; i < segs.count; i++) {
                if ([segs[i] length]) [tail addObject:segs[i]];
            }
            NSString *joined = [tail componentsJoinedByString:@"/"];
            NSString *decoded = [joined stringByRemovingPercentEncoding];
            if (decoded.length &&
                ([decoded hasPrefix:@"http://"] || [decoded hasPrefix:@"https://"])) {
                target = decoded;
            }
        }

        [self proxyRequest:client method:method reqHeaders:reqHeaders entry:entry target:target];
    }
}

- (void)proxyRequest:(int)client
              method:(NSString *)method
          reqHeaders:(NSDictionary<NSString *, NSString *> *)reqHeaders
               entry:(KKProxyEntry *)entry
              target:(NSString *)target {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:target]];
    req.HTTPMethod = method;
    req.timeoutInterval = 15;

    // 先铺原始请求头（Referer / UA / Cookie…）
    for (NSString *k in entry.headers) {
        if ([_hopHeaders containsObject:k.lowercaseString]) continue;
        [req setValue:entry.headers[k] forHTTPHeaderField:k];
    }
    // 再铺客户端（电视）的头，但不覆盖源站鉴权相关的。
    // Range 必须从客户端透传，否则拖进度条失效。
    for (NSString *k in reqHeaders) {
        NSString *low = k.lowercaseString;
        if ([_hopHeaders containsObject:low]) continue;
        if ([low isEqualToString:@"range"] ||
            [low isEqualToString:@"if-range"] ||
            [low isEqualToString:@"accept"] ||
            [low isEqualToString:@"user-agent"]) {
            [req setValue:reqHeaders[k] forHTTPHeaderField:k];
        }
    }
    // 源站要的 UA 优先用 App 里带的，没有才用系统的
    if (!entry.headers[@"User-Agent"] && !entry.headers[@"user-agent"]) {
        [req setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
    forHTTPHeaderField:@"User-Agent"];
    }

    // 用流式转发，不用 dataTaskWithRequest 的 completionHandler。
    //
    // 原因：completionHandler 会把整个响应体读进内存。整片 mp4
    // 常见 200MB～2GB，在手机上直接 OOM 被系统杀掉——用户看到的是
    // "一投屏 App 就闪退"，而日志里没有任何我们的错误（系统杀的）。
    // 流式转发则是来一块转一块，内存占用只跟块大小有关。
    KKProxyStreamer *s = [[KKProxyStreamer alloc] initWithRequest:req
                                                          client:client
                                                           owner:self
                                                          target:target];
    [self.streamers addObject:s];
    [s begin];
}


/// 把 m3u8 里所有 URI 换成代理地址。
///
/// 三种 URI 都要处理，漏一种就是特定片源必然失败：
///   1. 裸行（分片）：segment.ts
///   2. 标签带 URI 属性：#EXT-X-KEY:URI="key.key" / #EXT-X-MAP:URI="init.mp4"
///   3. 子播放列表（多码率）：variant.m3u8
- (NSString *)rewritePlaylist:(NSString *)text
                      baseURL:(NSString *)baseURL
                        token:(NSString *)token
                         port:(uint16_t)port {
    if (!text.length || !token.length) return text ?: @"";

    NSURL *base = [NSURL URLWithString:baseURL];
    NSString *host = [self localIPAddress];
    NSString *prefix = [NSString stringWithFormat:@"http://%@:%u/p/%@/", host, port, token];

    NSMutableArray *out = [NSMutableArray array];
    for (NSString *rawLine in [text componentsSeparatedByString:@"\n"]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];

        if (!line.length) { [out addObject:rawLine]; continue; }

        if ([line hasPrefix:@"#"]) {
            // 处理 #EXT-X-KEY / #EXT-X-MAP / #EXT-X-MEDIA / #EXT-X-I-FRAME-STREAM-INF
            // 里的 URI="..."
            if ([line containsString:@"URI=\""]) {
                NSRange r1 = [line rangeOfString:@"URI=\""];
                if (r1.location != NSNotFound) {
                    NSUInteger start = r1.location + r1.length;
                    NSRange rest = NSMakeRange(start, line.length - start);
                    NSRange r2 = [line rangeOfString:@"\"" options:0 range:rest];
                    if (r2.location != NSNotFound) {
                        NSString *uri = [line substringWithRange:NSMakeRange(start, r2.location - start)];
                        NSString *abs = [self absoluteURI:uri base:base];
                        NSString *proxied = [prefix stringByAppendingString:
                                             [self urlSafe:abs]];
                        NSString *newLine = [line stringByReplacingCharactersInRange:
                            NSMakeRange(start, r2.location - start) withString:proxied];
                        [out addObject:newLine];
                        continue;
                    }
                }
            }
            [out addObject:line];
            continue;
        }

        // 裸 URI 行
        NSString *abs = [self absoluteURI:line base:base];
        [out addObject:[prefix stringByAppendingString:[self urlSafe:abs]]];
    }

    return [out componentsJoinedByString:@"\n"];
}

/// 相对地址转绝对。m3u8 里的相对路径是相对"播放列表自身"的。
- (NSString *)absoluteURI:(NSString *)uri base:(NSURL *)base {
    if (!uri.length) return @"";
    if ([uri hasPrefix:@"http://"] || [uri hasPrefix:@"https://"]) return uri;
    NSURL *u = [NSURL URLWithString:uri relativeToURL:base];
    return u.absoluteString ?: uri;
}

/// 代理 URL 的路径里要再嵌一个完整 URL，必须转义，
/// 否则 http:// 里的 // 会被当成路径分隔符。
- (NSString *)urlSafe:(NSString *)s {
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
    return [s stringByAddingPercentEncodingWithAllowedCharacters:allowed] ?: s;
}

#pragma mark - 响应

- (void)respond:(int)client code:(NSInteger)code text:(NSString *)text {
    NSData *b = [text dataUsingEncoding:NSUTF8StringEncoding];
    [self sendResponse:client code:code type:@"text/plain; charset=utf-8"
                length:b.length extra:nil body:b];
}

- (void)sendResponse:(int)client
                code:(NSInteger)code
                type:(NSString *)type
              length:(NSUInteger)length
               extra:(NSDictionary<NSString *, NSString *> *)extra
                body:(NSData *)body {
    NSMutableString *h = [NSMutableString string];
    [h appendFormat:@"HTTP/1.1 %ld %@\r\n", (long)code,
        code == 200 ? @"OK" : (code == 206 ? @"Partial Content" :
        (code == 404 ? @"Not Found" : (code == 502 ? @"Bad Gateway" : @"Error")))];
    [h appendFormat:@"Content-Type: %@\r\n", type ?: @"application/octet-stream"];
    [h appendFormat:@"Content-Length: %lu\r\n", (unsigned long)length];
    // 电视要能跨域拿，否则某些机型拒绝播放
    [h appendString:@"Access-Control-Allow-Origin: *\r\n"];
    [h appendString:@"Accept-Ranges: bytes\r\n"];
    [h appendString:@"Connection: close\r\n"];
    for (NSString *k in extra) {
        [h appendFormat:@"%@: %@\r\n", k, extra[k]];
    }
    [h appendString:@"\r\n"];

    NSMutableData *packet = [[h dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    if (body.length) [packet appendData:body];

    // 循环写，send 不保证一次写完（大分片尤其）
    const uint8_t *bytes = packet.bytes;
    NSUInteger total = packet.length;
    NSUInteger sent = 0;
    while (sent < total) {
        ssize_t n = send(client, bytes + sent, total - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
    close(client);
}

#pragma mark - KKProxyServer (Internal) 的实现

/// 只发响应头，body 由调用方逐块 send。
/// 用于媒体流：Content-Length 可能为 0（chunked 上游），
/// 这时不能写死长度，否则电视只读前 N 字节就停。
- (void)sendStreamHeader:(int)client
                    code:(NSInteger)code
                    type:(NSString *)type
                  length:(NSUInteger)length
                   extra:(NSDictionary<NSString *, NSString *> *)extra {
    NSMutableString *h = [NSMutableString string];
    NSString *reason = @"OK";
    if (code == 206) reason = @"Partial Content";
    else if (code == 404) reason = @"Not Found";
    else if (code >= 500) reason = @"Bad Gateway";
    else if (code >= 400) reason = @"Error";

    [h appendFormat:@"HTTP/1.1 %ld %@\r\n", (long)code, reason];
    [h appendFormat:@"Content-Type: %@\r\n", type ?: @"application/octet-stream"];
    // 长度 0 表示未知：直接不发这个头，让客户端按连接关闭判断结束。
    // 发 "Content-Length: 0" 会让电视认为没有内容，直接报错。
    if (length > 0) {
        [h appendFormat:@"Content-Length: %lu\r\n", (unsigned long)length];
    }
    [h appendString:@"Access-Control-Allow-Origin: *\r\n"];
    [h appendString:@"Accept-Ranges: bytes\r\n"];
    [h appendString:@"Connection: close\r\n"];
    for (NSString *k in extra) {
        // Content-Length 已经在上面按 length 参数写过了，别写两遍
        if ([k.lowercaseString isEqualToString:@"content-length"]) continue;
        [h appendFormat:@"%@: %@\r\n", k, extra[k]];
    }
    [h appendString:@"\r\n"];

    NSData *d = [h dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *bytes = d.bytes;
    NSUInteger total = d.length;
    NSUInteger sent = 0;
    while (sent < total) {
        ssize_t n = send(client, bytes + sent, total - sent, 0);
        if (n <= 0) return;
        sent += (NSUInteger)n;
    }
}

/// 一次性发完整响应（含 body），发完关连接。
/// 用于 m3u8 重写结果、错误页这类小响应。
- (void)sendWholeResponse:(int)client
                     code:(NSInteger)code
                     type:(NSString *)type
                     body:(NSData *)body {
    NSMutableString *h = [NSMutableString string];
    NSString *reason = @"OK";
    if (code == 206) reason = @"Partial Content";
    else if (code == 404) reason = @"Not Found";
    else if (code >= 500) reason = @"Bad Gateway";
    else if (code >= 400) reason = @"Error";

    [h appendFormat:@"HTTP/1.1 %ld %@\r\n", (long)code, reason];
    [h appendFormat:@"Content-Type: %@\r\n", type ?: @"application/octet-stream"];
    [h appendFormat:@"Content-Length: %lu\r\n", (unsigned long)body.length];
    [h appendString:@"Access-Control-Allow-Origin: *\r\n"];
    [h appendString:@"Accept-Ranges: bytes\r\n"];
    [h appendString:@"Connection: close\r\n\r\n"];

    NSMutableData *packet = [[h dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    if (body.length) [packet appendData:body];

    const uint8_t *bytes = packet.bytes;
    NSUInteger total = packet.length;
    NSUInteger sent = 0;
    while (sent < total) {
        ssize_t n = send(client, bytes + sent, total - sent, 0);
        if (n <= 0) break;
        sent += (NSUInteger)n;
    }
    close(client);
}

/// 按原始地址反查 token。
/// streamer 只知道 target（真实上游地址），重写播放列表时需要
/// token 才能生成代理前缀，所以必须能反查。
- (NSString *)tokenForEntryByAddress:(NSString *)address {
    if (!address.length) return @"";
    __block NSString *found = nil;
    [_lock lock];
    [_entries enumerateKeysAndObjectsUsingBlock:^(NSString *k, KKProxyEntry *v, BOOL *stop) {
        // 入口地址完全相等；或者是入口地址同域下的子路径（分片/子列表）。
        // 后一种情况用 host+path 前缀匹配，避免为每个分片都新建登记。
        if ([v.url isEqualToString:address]) { found = k; *stop = YES; return; }
        NSString *vHost = [NSURL URLWithString:v.url].host;
        NSString *aHost = [NSURL URLWithString:address].host;
        if (vHost.length && [vHost isEqualToString:aHost]) { found = k; *stop = YES; }
    }];
    [_lock unlock];
    return found ?: @"";
}

- (void)removeStreamer:(KKProxyStreamer *)s {
    if (!s) return;
    @synchronized (self) {
        [_streamers removeObject:s];
    }
}

@end

@implementation KKProxyStreamer

- (instancetype)initWithRequest:(NSURLRequest *)req
                         client:(int)client
                          owner:(KKProxyServer *)owner
                         target:(NSString *)target {
    if ((self = [super init])) {
        _client = client;
        _owner = owner;
        _target = [target copy];
        _playlistBuf = [NSMutableData data];
        NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        c.timeoutIntervalForRequest = 20;
        // 整片下载可能很久，给 1 小时
        c.timeoutIntervalForResource = 3600;
        c.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        _session = [NSURLSession sessionWithConfiguration:c delegate:self delegateQueue:nil];
        _task = [_session dataTaskWithRequest:req];
    }
    return self;
}

- (void)begin { [_task resume]; }

- (void)finish {
    [self.task cancel];
    [self.session invalidateAndCancel];
    [self.owner removeStreamer:self];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    if (error) KKLog(@"streamer 结束（含错误）: %@", error.localizedDescription);

    // 播放列表模式：数据全部收在这里才处理。
    // 必须在这个回调里做，不能在 didReceiveData 里做——
    // 那时还不知道响应是成功还是被截断的。
    if (self.playlistMode) {
        NSInteger code = [(NSHTTPURLResponse *)task.response statusCode];
        if (!error && self.playlistBuf.length) {
            [self flushPlaylistWithCode:code];
        } else {
            [self.owner sendWholeResponse:self.client code:code ?: 502
                                     type:@"text/plain; charset=utf-8"
                                     body:[@"upstream playlist error" dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }

    close(self.client);
    [self finish];
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    NSHTTPURLResponse *hr = (NSHTTPURLResponse *)response;
    NSString *ctype = hr.allHeaderFields[@"Content-Type"] ?: @"application/octet-stream";
    NSInteger code = hr.statusCode;

    NSString *lowTarget = self.target.lowercaseString;
    self.playlistMode = [ctype containsString:@"mpegurl"] ||
                        ([lowTarget containsString:@".m3u8"] &&
                         ![ctype containsString:@"video"] &&
                         ![ctype containsString:@"octet-stream"]);

    if (self.playlistMode) {
        // 播放列表很小（几 KB），先缓冲完全部再重写，
        // 不能边收边发——重写需要看到完整内容才能算对相对路径。
        completionHandler(NSURLSessionResponseAllow);
        return;
    }

    // 媒体流：立刻发响应头，然后逐块转字节
    NSMutableDictionary *extra = [NSMutableDictionary dictionary];
    NSString *cr = hr.allHeaderFields[@"Content-Range"];
    if (cr) extra[@"Content-Range"] = cr;
    NSString *cl = hr.allHeaderFields[@"Content-Length"];
    NSString *ar = hr.allHeaderFields[@"Accept-Ranges"];
    if (ar) extra[@"Accept-Ranges"] = ar;

    [self.owner sendStreamHeader:self.client
                            code:code
                            type:ctype
                          length:cl ? (NSUInteger)cl.longLongValue : 0
                           extra:extra];
    self.headerSent = YES;

    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data {
    if (self.playlistMode) {
        [self.playlistBuf appendData:data];
        return;
    }
    if (!self.headerSent) return;

    const uint8_t *bytes = data.bytes;
    NSUInteger total = data.length;
    NSUInteger sent = 0;
    while (sent < total) {
        ssize_t n = send(self.client, bytes + sent, total - sent, 0);
        if (n <= 0) {
            // 电视断开（用户换台/关电视）是常态，不是错误
            [self finish];
            return;
        }
        sent += (NSUInteger)n;
    }
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
 willCacheResponse:(NSCachedURLResponse *)proposedResponse
 completionHandler:(void (^)(NSCachedURLResponse *))completionHandler {
    // 视频流不缓存，省内存
    completionHandler(nil);
}

/// 播放列表收完后的收尾：重写并发出去。
- (void)flushPlaylistWithCode:(NSInteger)code {
    NSString *text = [[NSString alloc] initWithData:self.playlistBuf encoding:NSUTF8StringEncoding];
    if (!text) text = [[NSString alloc] initWithData:self.playlistBuf encoding:NSISOLatin1StringEncoding];
    NSString *token = [self.owner tokenForEntryByAddress:self.target];
    NSString *rewritten = [self.owner rewritePlaylist:text
                                              baseURL:self.target
                                                token:token
                                                 port:self.owner.port];
    NSData *out = [rewritten dataUsingEncoding:NSUTF8StringEncoding];
    [self.owner sendWholeResponse:self.client
                             code:code == 0 ? 200 : code
                             type:@"application/vnd.apple.mpegurl"
                             body:out];
}

@end
