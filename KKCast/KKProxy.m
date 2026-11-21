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
#import <sys/time.h>

/// 内存里最多缓存多大的上游响应。超过这个就走落盘 + 流式发送。
/// 48MB 是权衡：ts 分片通常 1-5MB，远低于它；mp4 整片可能几百 MB，
/// 一次性读进内存会在这台手机上直接 OOM 被系统杀掉。
static const NSUInteger kInlineMaxBytes = 48 * 1024 * 1024;

/// 一次写操作最多允许"零进展"多久（秒）。
///
/// 电视 seek 时播放器会 flush 缓冲区、重建 demuxer，期间可能几百毫秒
/// 到几秒不读 socket，属于正常行为；但不会 45 秒一个字节都不收。
/// 超过这个时长才认为对端确实不要了。
static const NSTimeInterval kSendStallLimit = 45.0;

static NSTimeInterval kk_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (NSTimeInterval)tv.tv_sec + (NSTimeInterval)tv.tv_usec / 1000000.0;
}

/// 尽力把 buf 的 len 字节写到 fd，返回**实际写出**的字节数。
///
/// 返回值 < len 表示对端确实不再接收，调用方应当收尾这条连接。
///
/// ── 为什么不能直接 send 完事（这是"快进后进度卡死"的头号原因）──
///
/// client fd 上设了 SO_SNDTIMEO。对端接收窗口满时 send 会阻塞到超时，
/// 然后返回 -1 且 errno == EAGAIN。**EAGAIN 的语义是"现在写不进去"，
/// 不是"对端不要了"**。原来的写法把所有 n <= 0 一律当成断开：
///
///   电视快进 → 播放器 flush buffer 暂停读几百毫秒
///            → 我们的 send 超时返回 EAGAIN
///            → 判定"电视断开" → close(client) + 取消上游任务
///            → 电视侧数据流中断，进度条停在快进位置不动
///
/// 正确做法：EAGAIN 时用 select 等 socket 可写再重试，只在
/// "长时间零进展"或"真错误（EPIPE / ECONNRESET）"时才放弃。
/// 这样慢速客户端（电视缓冲小、WiFi 抖动）也能把整片推完。
static size_t kk_send_all(int fd, const uint8_t *buf, size_t len) {
    if (fd <= 0 || !buf || len == 0) return 0;

    size_t sent = 0;
    NSTimeInterval stallStart = 0;   // 0 表示当前不处于停滞状态

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
            stallStart = 0;          // 有进展，清掉停滞计时
            continue;
        }
        if (n < 0 && errno == EINTR) continue;

        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            NSTimeInterval now = kk_now();
            if (stallStart == 0) stallStart = now;
            if (now - stallStart >= kSendStallLimit) {
                KKLog(@"send 停滞 %.0fs 零进展，放弃 fd=%d（已写 %zu/%zu）",
                      kSendStallLimit, fd, sent, len);
                break;
            }
            // 等可写，最多 1 秒一片，回来重试并复查停滞时限
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv = {1, 0};
            select(fd + 1, NULL, &wfds, NULL, &tv);
            continue;
        }
        break;   // EPIPE / ECONNRESET / 其他真错误
    }
    return sent;
}

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
/// 请求自带的 token。重写子播放列表时必须用它，不能再靠
/// tokenForEntryByAddress 反查（见 flushPlaylistWithCode 的说明）。
@property (nonatomic, copy) NSString *token;
@property (nonatomic, assign) BOOL headerSent;
@property (nonatomic, assign) BOOL playlistMode;
/// 防止重复 close 同一个 fd（见 closeClientOnce 的说明）
@property (nonatomic, assign) BOOL clientClosed;
@property (nonatomic, strong) NSMutableData *playlistBuf;
- (instancetype)initWithRequest:(NSURLRequest *)req
                         client:(int)client
                          owner:(KKProxyServer *)owner
                         target:(NSString *)target
                          token:(NSString *)token;
- (void)begin;
- (void)finish;
- (void)flushPlaylistWithCode:(NSInteger)code;
- (void)closeClientOnce;
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

        // ★★ 必须给 accept 出来的 fd 单独设 SO_NOSIGPIPE ★★
        //
        // 这是"点投屏后容易闪退"的头号原因，而且极难查：
        //   - 监听 fd 上设的 socket 选项**不会被 accept 的新 fd 继承**。
        //     上面 startOnPort: 里那行 setsockopt(SO_NOSIGPIPE) 只作用于
        //     监听 fd，对每个新连接无效。
        //   - 电视的断连是常态：用户换台、拖进度、关电视、甚至 HLS
        //     播放器主动断开旧连接去请求新分片，都会让对端先关。
        //   - 对端已关时 send() 会触发 SIGPIPE。iOS 上 SIGPIPE 的默认
        //     处置是**终止整个进程**，不抛 ObjC 异常、不写 crash log 的
        //     业务栈 —— 用户看到的就是"点投屏，App 直接没了"，
        //     而日志里只有上一条正常记录，看不出任何线索。
        //   - 拖进度条时最密集（旧连接被频繁掐断），这也解释了为什么
        //     "快进/换台"时更容易闪退。
        int yes = 1;
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));

        // 给 client 设收发超时，防止对端"半死不活"时永久阻塞。
        //
        // 场景：电视 seek 时可能保留 TCP 连接但不再读数据（缓冲区满），
        // 或者发了残包就卡住。此时：
        //   - recv 阻塞 → 这条串行队列永远不释放，连接泄漏
        //   - send 阻塞 → didReceiveData 永不返回，NSURLSession 停止
        //     收数据，上游 TCP 窗口打满
        // 累积几条之后 GCD 线程被占满，整个 App 的网络一起卡死，
        // 表现就是"进度条不动了"。
        // 超时后 send/recv 返回 -1 + EAGAIN，走既有的失败分支清理。
        struct timeval snd_to = {8, 0};     // 8 秒发不出去就认为对端不要了
        struct timeval rcv_to = {15, 0};    // 15 秒收不到请求头就放弃
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

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
        NSTimeInterval deadline = kk_now() + 15.0;
        while (head.length < 8192) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n < 0) {
                // client fd 上有 SO_RCVTIMEO，对端发了半截头就卡住时
                // recv 返回 -1/EAGAIN。原来直接 break 当成"没数据"，
                // 已经收到的部分被丢掉；这里区分两种情况：
                // 已经读到内容就继续尝试，完全没读到且超时则放弃。
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (head.length == 0 || kk_now() >= deadline) break;
                    continue;
                }
                break;
            }
            if (n == 0) break;   // 对端正常关闭
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

        [self proxyRequest:client method:method reqHeaders:reqHeaders entry:entry target:target token:token];
    }
}

- (void)proxyRequest:(int)client
              method:(NSString *)method
          reqHeaders:(NSDictionary<NSString *, NSString *> *)reqHeaders
               entry:(KKProxyEntry *)entry
              target:(NSString *)target
               token:(NSString *)token {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:target]];
    req.HTTPMethod = method;
    // 快进（seek）时电视会带 Range 从远处重新请求，源站要做切片定位、
    // 有时还要回源转码，首字节比从头播慢得多。原来写死 15 秒，
    // 源站稍慢就超时断流，表现正是"快进之后卡住不动"。
    // 这里放宽到 30 秒；真正的卡死由 kk_send_all 的停滞检测兜住。
    req.timeoutInterval = 30;

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
                                                          target:target
                                                           token:token];
    // ★ add 必须和 removeStreamer: 用同一把锁。
    //
    // 原来这里是无锁的 [_streamers addObject:s]，而删除那边用的是
    // @synchronized(self)。两把不同的"锁"等于没有锁：
    // NSMutableSet 在并发读写时会崩在 objc_msgSend / 内部哈希表重排，
    // 崩溃栈看起来在系统库里，与我们的代码毫无关系，极难归因。
    //
    // 投屏时的并发量正好踩在这个窗口上：拖进度会让电视瞬间断开旧连接
    // 并发起新连接，add 与 remove 几乎同时发生。
    @synchronized (self) {
        [_streamers addObject:s];
    }
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
    // 空 token 时返回空串（而不是原样返回 text）。
    //
    // 原写法 `return text ?: @""` 会把**未重写**的播放列表当成结果交出去：
    // 里面全是原始分片地址，电视会直连源站，遇防盗链就静默卡死。
    // 宁可明确失败（上层会回 502），也不要把错误数据当成功交付。
    if (!text.length || !token.length) return @"";

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

    kk_send_all(client, packet.bytes, packet.length);
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
    //
    // ★ 判据是 `extra 里有没有 Content-Length`，不能用 `length > 0`。
    //   原写法把"上游明确说了 0 字节"和"我们不知道长度"混成一件事：
    //   空分片 / 204 / 空的 INIT 段上游会回 Content-Length: 0，
    //   我们却当成未知长度，不发该头，电视就一直等连接关闭，
    //   表现为"某个分片卡住、进度不走"。
    BOOL lengthKnown = (length > 0);
    if (!lengthKnown) {
        for (NSString *k in extra) {
            if ([k.lowercaseString isEqualToString:@"content-length"]) {
                lengthKnown = YES;
                break;
            }
        }
    }
    if (lengthKnown) {
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
    kk_send_all(client, d.bytes, d.length);
}

/// 一次性发完整响应（含 body），**不关连接**。
///
/// 关连接的责任统一交给 KKProxyStreamer 的 closeClientOnce：
/// 原来这里自己 close(client)，随后 didCompleteWithError 又走
/// closeClientOnce 关一次。dylib 的 _clientClosed 标志没被置位，
/// 于是同一 fd 被关两次。fd 号在第一次 close 后立刻会被系统复用给
/// 新连接（电视快进时会并发发起新请求），第二次 close 就把**别人的
/// 连接**关掉了 —— 现象是"快进一下，投屏就再也连不上"。
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

    kk_send_all(client, packet.bytes, packet.length);
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
                         target:(NSString *)target
                          token:(NSString *)token {
    if ((self = [super init])) {
        _client = client;
        _owner = owner;
        _target = [target copy];
        _token = [token copy];
        _playlistBuf = [NSMutableData data];
        NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        // 单次请求等待首字节的时限。快进到远处时需要重新定位，
        // 5 秒太紧，给 20 秒；整片下载另由 timeoutIntervalForResource 控制。
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

/// 关闭 client socket，且**只关一次**。
///
/// 为什么必须防重入：finish 有两条路径会走到
///   1. didReceiveData 里 send 失败（电视断开）→ 直接 finish
///   2. 之后 upstream 也结束 → didCompleteWithError → close(client)
/// 两条都 close 同一个 fd。fd 号会被系统立刻复用给新连接，
/// 第二次 close 就把**别的连接**关掉了。
/// 现象是"拖一次进度，投屏就再也连不上了"，或另一路请求莫名 502。
///
/// 用 @synchronized 保护标志位：两个回调可能在不同线程
/// （NSURLSession 的 delegate 队列 vs 我们自己的连接队列）。
- (void)closeClientOnce {
    BOOL needClose = NO;
    @synchronized (self) {
        if (!_clientClosed) {
            _clientClosed = YES;
            needClose = YES;
        }
    }
    if (needClose && self.client > 0) {
        close(self.client);
    }
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
            // 上游播放列表失败时的兜底错误页。
            // 注意 sendWholeResponse 现在不关 fd，统一由下面的
            // closeClientOnce 收尾，避免同一 fd 被关两次。
            [self.owner sendWholeResponse:self.client code:code ?: 502
                                     type:@"text/plain; charset=utf-8"
                                     body:[@"upstream playlist error" dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }

    // 关连接统一在这里做，且只做一次。
    [self closeClientOnce];
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

    // kk_send_all 内部会把 SO_SNDTIMEO 的 EAGAIN 当作"暂时写不进去"
    // 并等待重试，只有真断开（EPIPE/ECONNRESET）或 45 秒零进展才
    // 返回不足量。这样电视快进时短暂不读 socket 不会误杀连接。
    //
    // 原写法 n <= 0 就判断开 → 快进触发 flush → send 超时 → 断流 →
    // 进度条停在快进位置不动。这是问题 3 的直连原因。
    size_t written = kk_send_all(self.client, data.bytes, data.length);
    if (written < data.length) {
        // 电视真的不要了（换台/关电视/超时）。
        //
        // headerSent 置 NO：NSURLSession 可能已经在队列里排了若干个
        // didReceiveData 回调，它们随后仍会对关闭的 fd 反复 send。
        // 置 NO 让那些回调直接 return。
        self.headerSent = NO;
        [self closeClientOnce];
        [self finish];
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

    // ★ token 直接用请求路径里带过来的那个，不要反查。
    //
    // 原来这里是 tokenForEntryByAddress:self.target，靠"原始地址反查
    // 登记表"来猜 token。但地址可能带会变的查询串（签名、时间戳、
    // 防盗链 token），反查用 host 前缀匹配，遇到同域不同 token 就
    // 猜错或猜空；猜空时 rewritePlaylist 会**原样返回**未重写的列表
    // （里面是原始分片地址），电视按播放列表的 host 去直连分片，
    // 照样 403/超时 —— 表现正是"拖动进度条之后卡住不动"。
    //
    // 请求路径 /p/<token>/... 里本来就带着 token，是权威来源。
    NSString *token = self.token;
    if (!token.length) {
        token = [self.owner tokenForEntryByAddress:self.target];
    }
    if (!token.length) {
        // 兜底也拿不到 token：绝不能回原始列表，那会让电视直连源站
        // 然后静默卡死。明确报错，至少行为可预期、日志可归因。
        KKLog(@"播放列表缺少 token，放弃重写: %@", self.target);
        [self.owner sendWholeResponse:self.client
                                 code:502
                                 type:@"text/plain; charset=utf-8"
                                 body:[@"playlist token lost" dataUsingEncoding:NSUTF8StringEncoding]];
        return;
    }

    NSString *rewritten = [self.owner rewritePlaylist:text
                                              baseURL:self.target
                                                token:token
                                                 port:self.owner.port];
    if (!rewritten.length) {
        KKLog(@"播放列表重写结果为空: %@", self.target);
        [self.owner sendWholeResponse:self.client
                                 code:502
                                 type:@"text/plain; charset=utf-8"
                                 body:[@"playlist rewrite failed" dataUsingEncoding:NSUTF8StringEncoding]];
        return;
    }
    NSData *out = [rewritten dataUsingEncoding:NSUTF8StringEncoding];
    [self.owner sendWholeResponse:self.client
                             code:code == 0 ? 200 : code
                             type:@"application/vnd.apple.mpegurl"
                             body:out];
}

@end
