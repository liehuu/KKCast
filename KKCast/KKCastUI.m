//
//  KKCastUI.m
//  悬浮投屏按钮 + 设备选择列表
//
//  为什么用悬浮按钮而不是去改 App 自己的播放器 UI：
//  宿主是纯 SwiftUI + 自绘播放器，它的控制条没有稳定可 hook 的
//  ObjC 类名（符号表已 strip），硬改视图层级要跟着它的版本走，
//  换个版本就白做。悬浮窗是**独立于宿主视图体系**的，
//  只要 App 在前台就一直在，不依赖宿主的任何内部结构。
//

#import "KKCast.h"
#import <objc/runtime.h>

#define kBtnSize 44.0

@interface KKCastUI ()
@property (nonatomic, strong) UIWindow *overlayWindow;
@property (nonatomic, strong) UIButton *castButton;
@property (nonatomic, copy) NSString *mediaURL;
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *mediaHeaders;
@property (nonatomic, copy) NSString *mediaTitle;
@property (nonatomic, strong) UIViewController *listVC;
@property (nonatomic, assign) BOOL proxyStarted;
@end

/// 私有方法全部在这里声明。
///
/// 为什么非要写：只在 @implementation 里定义而不声明，调用点出现在
/// 定义之前时，clang 会因为"看不到方法签名"报
/// -Wobjc-method-access / -Wundeclared-selector。这类警告在
/// 打开了 -Werror 的 CI 上等于编译失败，而且报的还是"可能不存在
/// 这个方法"，非常容易被误读成真的漏了实现。
@interface KKCastUI (Private)
- (UIWindow *)hostWindow;
- (void)showButtonIfNeeded;
- (void)bringOverlayToFront;
- (void)hideButton;
- (void)appDidBecomeActive;
- (void)onTapCast;
- (UIViewController *)topViewController;
- (UIViewController *)makeDeviceListVC;
- (void)startDiscoveryForTable:(UITableView *)tv
                       spinner:(UIActivityIndicatorView *)spin
                          hint:(UILabel *)hint;
- (void)dismissList;
- (void)castToDevice:(KKCastDevice *)dev;
- (NSString *)didlForURL:(NSString *)url title:(NSString *)title;
- (void)toast:(NSString *)text;
@end

@implementation KKCastUI

+ (instancetype)shared {
    static KKCastUI *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [KKCastUI new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(appDidBecomeActive)
                                                     name:UIApplicationDidBecomeActiveNotification
                                                   object:nil];
    }
    return self;
}

#pragma mark - 对外

- (void)updateCurrentMediaURL:(NSString *)url
                      headers:(NSDictionary<NSString *, NSString *> *)headers
                        title:(NSString *)title {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.mediaURL = url;
        self.mediaHeaders = headers;
        self.mediaTitle = title;

        if (!url.length) {
            [self hideButton];
            return;
        }
        [self showButtonIfNeeded];
    });
}

#pragma mark - 窗口

/// 用一个独立的 UIWindow。
/// windowLevel 设成 Alert+1，能盖在宿主任何内容之上；
/// 同时 userInteractionEnabled 只作用在按钮上，不能挡住播放器手势。
- (UIWindow *)hostWindow {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        UIWindowScene *ws = (UIWindowScene *)scene;
        if (ws.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *w in ws.windows) {
            if (w.isKeyWindow) return w;
        }
        if (ws.windows.count) return ws.windows.firstObject;
    }
    return nil;
}

- (void)showButtonIfNeeded {
    if (_castButton) {
        _castButton.hidden = NO;
        [self bringOverlayToFront];
        return;
    }

    UIWindow *host = [self hostWindow];
    if (!host) {
        // 宿主还没起窗口，等一下再试。播放开始时几乎不可能发生，
        // 但冷启动立刻恢复播放的场景会遇到。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (self.mediaURL.length) [self showButtonIfNeeded];
        });
        return;
    }

    // 直接挂在宿主窗口上，不开新 UIWindow。
    // 新 UIWindow 在 iOS 13+ 多场景下会和宿主的 scene 打架，
    // 出现过窗口黑屏遮挡全屏的案例。挂 subview 最稳。
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.frame = CGRectMake(0, 0, kBtnSize, kBtnSize);
    b.layer.cornerRadius = kBtnSize / 2;
    b.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55];
    b.layer.borderWidth = 1.5;
    b.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.75].CGColor;
    [b setTitle:@"📺" forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:22];
    [b addTarget:self action:@selector(onTapCast) forControlEvents:UIControlEventTouchUpInside];

    // 放在右上角，避让刘海。用安全区算，不写死 44。
    CGFloat topInset = host.safeAreaInsets.top;
    CGFloat rightInset = host.safeAreaInsets.right;
    b.center = CGPointMake(host.bounds.size.width - rightInset - kBtnSize / 2 - 12,
                           topInset + kBtnSize / 2 + 8);

    // 跟随旋转/尺寸变化
    b.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleBottomMargin;

    [host addSubview:b];
    _castButton = b;

    KKLog(@"投屏按钮已显示");
}

- (void)bringOverlayToFront {
    if (_castButton.superview) {
        [_castButton.superview bringSubviewToFront:_castButton];
    }
}

- (void)hideButton {
    [_castButton removeFromSuperview];
    _castButton = nil;
}

- (void)appDidBecomeActive {
    // 回到前台时宿主的视图可能重建过，按钮被连带移除了。
    // 重新挂一次，否则用户切回来发现按钮没了。
    if (_mediaURL.length && (!_castButton || !_castButton.superview)) {
        _castButton = nil;
        [self showButtonIfNeeded];
    }
}

#pragma mark - 交互

- (void)onTapCast {
    // 轻反馈，让用户确认点到了
    UIImpactFeedbackGenerator *g = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
    [g impactOccurred];

    if (!_proxyStarted) {
        _proxyStarted = [[KKProxyServer shared] startOnPort:0];
        if (!_proxyStarted) {
            [self toast:@"本地代理启动失败，无法投屏"];
            return;
        }
        KKLog(@"代理端口 %u", [KKProxyServer shared].port);
    }

    UIViewController *list = [self makeDeviceListVC];
    _listVC = list;

    UIViewController *presenter = [self topViewController];
    if (!presenter) { [self toast:@"界面未就绪"]; return; }

    list.modalPresentationStyle = UIModalPresentationFormSheet;
    [presenter presentViewController:list animated:YES completion:nil];
}

- (UIViewController *)topViewController {
    UIWindow *host = [self hostWindow];
    UIViewController *vc = host.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

#pragma mark - 设备列表

- (UIViewController *)makeDeviceListVC {
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor systemBackgroundColor];

    UILabel *title = [UILabel new];
    title.text = @"选择投屏设备";
    title.font = [UIFont boldSystemFontOfSize:17];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [vc.view addSubview:title];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setTitle:@"关闭" forState:UIControlStateNormal];
    [close addTarget:self action:@selector(dismissList) forControlEvents:UIControlEventTouchUpInside];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [vc.view addSubview:close];

    UITableView *tv = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    tv.translatesAutoresizingMaskIntoConstraints = NO;
    tv.tag = 9001;
    tv.rowHeight = 60;
    [vc.view addSubview:tv];

    UIActivityIndicatorView *spin = [[UIActivityIndicatorView alloc]
                                     initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    spin.translatesAutoresizingMaskIntoConstraints = NO;
    spin.tag = 9002;
    [spin startAnimating];
    [vc.view addSubview:spin];

    UILabel *hint = [UILabel new];
    hint.text = @"正在搜索同一 WiFi 下的电视…";
    hint.font = [UIFont systemFontOfSize:13];
    hint.textColor = [UIColor secondaryLabelColor];
    hint.textAlignment = NSTextAlignmentCenter;
    hint.translatesAutoresizingMaskIntoConstraints = NO;
    hint.tag = 9003;
    [vc.view addSubview:hint];

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.topAnchor constant:14],
        [title.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],

        [close.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [close.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor constant:-16],

        [tv.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:12],
        [tv.leadingAnchor constraintEqualToAnchor:vc.view.leadingAnchor],
        [tv.trailingAnchor constraintEqualToAnchor:vc.view.trailingAnchor],
        [tv.bottomAnchor constraintEqualToAnchor:vc.view.bottomAnchor],

        [spin.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [spin.centerYAnchor constraintEqualToAnchor:vc.view.centerYAnchor],

        [hint.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [hint.topAnchor constraintEqualToAnchor:spin.bottomAnchor constant:10],
    ]];

    // 用 objc 关联对象把数据源挂上去，避免再多一个类文件
    objc_setAssociatedObject(tv, "kkcast.devices", @[], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    tv.dataSource = (id<UITableViewDataSource>)self;
    tv.delegate = (id<UITableViewDelegate>)self;

    [self startDiscoveryForTable:tv spinner:spin hint:hint];
    return vc;
}

- (void)startDiscoveryForTable:(UITableView *)tv
                       spinner:(UIActivityIndicatorView *)spin
                          hint:(UILabel *)hint {
    __weak typeof(self) weakSelf = self;
    __weak UITableView *weakTV = tv;
    [[KKDLNA shared] discoverWithCompletion:^(NSArray<KKCastDevice *> *devices) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        [spin stopAnimating];
        spin.hidden = YES;
        objc_setAssociatedObject(weakTV, "kkcast.devices", devices, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [weakTV reloadData];

        if (devices.count == 0) {
            hint.text = @"没找到电视。请确认：手机和电视在同一 WiFi、电视已开机";
        } else {
            hint.text = [NSString stringWithFormat:@"找到 %lu 台设备", (unsigned long)devices.count];
        }
    }];
}

- (void)dismissList {
    [_listVC dismissViewControllerAnimated:YES completion:nil];
    _listVC = nil;
}

#pragma mark - UITableView

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    NSArray *d = objc_getAssociatedObject(tableView, "kkcast.devices");
    return d.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cid = @"kkcast.cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid];
    }
    NSArray<KKCastDevice *> *d = objc_getAssociatedObject(tableView, "kkcast.devices");
    if (indexPath.row < (NSInteger)d.count) {
        KKCastDevice *dev = d[indexPath.row];
        cell.textLabel.text = dev.friendlyName;
        cell.detailTextLabel.text = dev.modelName.length ? dev.modelName : dev.location;
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.imageView.image = [UIImage systemImageNamed:@"tv"];
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSArray<KKCastDevice *> *d = objc_getAssociatedObject(tableView, "kkcast.devices");
    if (indexPath.row >= (NSInteger)d.count) return;
    KKCastDevice *dev = d[indexPath.row];
    [self castToDevice:dev];
}

#pragma mark - 投屏

- (void)castToDevice:(KKCastDevice *)dev {
    if (!_mediaURL.length) { [self toast:@"当前没有可投的影片"]; return; }

    [self toast:[NSString stringWithFormat:@"正在投到 %@…", dev.friendlyName]];

    // 先登记到代理，拿到电视能访问的地址。
    // 直接把 _mediaURL 给电视在带防盗链的源上必然失败。
    NSString *proxied = [[KKProxyServer shared] registerURL:_mediaURL headers:_mediaHeaders];

    // 有代理就用代理，没有（启动失败）退回原始地址试试，
    // 至少不会因为代理问题完全不能投。
    NSString *playURL = proxied.length ? proxied : _mediaURL;

    NSString *didl = [self didlForURL:playURL title:_mediaTitle ?: @"视频"];

    __weak typeof(self) weakSelf = self;
    [[KKDLNA shared] playURL:playURL metadata:didl onDevice:dev completion:^(BOOL ok, NSString *msg) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        if (ok) {
            [self toast:[NSString stringWithFormat:@"已投到 %@", dev.friendlyName]];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self dismissList];
            });
        } else {
            [self toast:[NSString stringWithFormat:@"投屏失败：%@", msg ?: @"未知错误"]];
        }
    }];
}

/// DIDL-Lite 元数据。
/// 有些电视不看这个也能播，但三星/部分索尼要求
/// protocolInfo 里明确写 MIME，否则拒绝加载。
- (NSString *)didlForURL:(NSString *)url title:(NSString *)title {
    NSString *esc = [title stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
    NSString *mime = @"video/mp4";
    if ([url containsString:@".m3u8"]) mime = @"application/vnd.apple.mpegurl";

    return [NSString stringWithFormat:
        @"<DIDL-Lite xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\" "
        @"xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
        @"xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\">"
        @"<item id=\"0\" parentID=\"-1\" restricted=\"1\">"
        @"<dc:title>%@</dc:title>"
        @"<upnp:class>object.item.videoItem</upnp:class>"
        @"<res protocolInfo=\"http-get:*:%@:*\">%@</res>"
        @"</item></DIDL-Lite>", esc, mime, url];
}

#pragma mark - Toast

- (void)toast:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *host = [self hostWindow];
        if (!host) return;

        UILabel *l = [UILabel new];
        l.text = text;
        l.font = [UIFont systemFontOfSize:14];
        l.textColor = [UIColor whiteColor];
        l.textAlignment = NSTextAlignmentCenter;
        l.numberOfLines = 2;
        l.backgroundColor = [UIColor colorWithWhite:0 alpha:0.82];
        l.layer.cornerRadius = 10;
        l.clipsToBounds = YES;
        l.alpha = 0;

        CGSize max = CGSizeMake(host.bounds.size.width - 80, 200);
        CGRect r = [text boundingRectWithSize:max
                                      options:NSStringDrawingUsesLineFragmentOrigin
                                   attributes:@{NSFontAttributeName: l.font}
                                      context:nil];
        CGFloat w = MIN(max.width, r.size.width + 32);
        CGFloat h = r.size.height + 22;
        l.frame = CGRectMake((host.bounds.size.width - w) / 2,
                             host.bounds.size.height - h - 100, w, h);
        l.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleLeftMargin |
                             UIViewAutoresizingFlexibleRightMargin;
        [host addSubview:l];

        [UIView animateWithDuration:0.2 animations:^{ l.alpha = 1; } completion:^(BOOL f) {
            [UIView animateWithDuration:0.25 delay:1.8 options:0 animations:^{ l.alpha = 0; }
                             completion:^(BOOL f2) { [l removeFromSuperview]; }];
        }];
    });
}

@end