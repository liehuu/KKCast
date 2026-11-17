# KKCast — 给可可影视加 DLNA 投屏

把 `com.FastenerC.Bolt`（可可影视 1.1.6）改造成能投 DLNA 电视的版本。

---

## 为什么要做这件事

可可影视的「投屏」按钮点进去是**「电视联播码」**，那是它自己的私有协议：

```
什么是"电视联播"？
"电视联播"：实现把APP端影片转到电视端播放，而不需要使用投屏功能。
* 此功能需要安装官方电视端APP，如未安装，可前往官网安装
```

也就是说，它要求你在电视上也装一个它的 App，输一串数字配对。这条路对
「电视上只装了一个通用 DLNA 接收器」的用户完全走不通。

二进制里查证（不是猜的）：

| 检索项 | 命中数 |
|---|---|
| `dlna` / `DLNA` / `ssdp` / `SSDP` / `UPnP` / `upnp` | **0** |
| `MediaRenderer` / `AVTransport` / `Chromecast` | **0** |
| 自身类 `VodTVPlayPopupView` / `VodTVPlayCodePopupView` | 各 1 |
| 自身方法 `connectTVPlayByQRCode:` | 1 |

结论：它没有任何 DLNA 实现，投屏只能靠 AirPlay（系统的）或它自己的联播码。
所以在它里面塞一整套 DLNA 客户端，是唯一能让它「出现在电视的投屏列表里」
或者「主动把片子推给电视」的办法。

---

## 目标 App 的实际结构（决定了方案）

原始 ipa：`kkys-116.ipa`，12,245,045 字节，sha256 `823853f5…a092a4`

| 项 | 值 | 对方案的影响 |
|---|---|---|
| Bundle ID | `com.FastenerC.Bolt` | 重签后保留 |
| 版本 | 1.1.6 | — |
| 架构 | arm64 | 只需处理一种 |
| `LC_ENCRYPTION_INFO.cryptid` | **0（未加密）** | **可直接改二进制**，这是整件事可行的前提 |
| 平台 / minos | iOS / 14.0 | — |
| 实现语言 | 纯 Swift + ObjC selector | Swift 符号被 strip，但 `AVFoundation` 的 selector 还在 |
| `__TEXT` header 空隙 | `0x2300 → 0x4000`，**7424 字节全零** | 可无移位插入 `LC_LOAD_DYLIB` |
| 反调试 / 完整性校验 | `ptrace` / `_dyld_image_count` / `isJailbroken` **全 0** | 不会阻碍注入 |
| `NSLocalNetworkUsageDescription` | **缺失** | 必须补，否则 iOS 14+ 静默拒绝局域网 |

泄漏的源码路径（说明它自带一个本地 HTTP 服务）：

```
/Users/incognito/Documents/workspace/iOS/movie/movie/views/vod/download/OfflinePlay/LocalHTTPServerManager.swift
```

这印证了一件事：**本地起 HTTP 服务给播放器喂流**是它本来就有的思路，
不是我们硬塞进去的异物。

---

## 方案

注入一个 ObjC dylib，做四件事：

```
┌─────────────────────────────────────────────────────┐
│  KKCast.dylib  (注入到 com.FastenerC.Bolt)          │
├─────────────────────────────────────────────────────┤
│  KKHook      挂钩 AVURLAsset / AVPlayerItem / AVPlayer│
│              → 拿到当前播放地址 + 请求头（Referer/UA）│
│                    ↓                                 │
│  KKCastUI    在右上角挂一个 📺 悬浮按钮               │
│              → 点开列出局域网内的 DLNA 电视            │
│                    ↓                                 │
│  KKProxy     起一个本地反向代理，把播放地址换成        │
│              http://<手机IP>:<port>/p/<token>/x.m3u8 │
│              → 补 Referer、重写 m3u8、透传 Range      │
│                    ↓                                 │
│  KKDLNA      SSDP 搜 MediaRenderer                    │
│              → SetAVTransportURI + Play              │
└─────────────────────────────────────────────────────┘
```

### 三个关键设计决定

**1. 为什么必须挂钩 `AVURLAsset -initWithURL:options:`**

某些源带防盗链。电视直连时不带 Referer，服务端返回 403，症状是
「投屏显示成功、电视黑屏」。而请求头藏在 `AVURLAsset` 的私有
options key `AVURLAssetHTTPHeaderFieldsKey` 里——这是唯一能拿到它的地方。

挂钩分三层兜底，任一层拿到地址就够：

| 层 | 选择器 | 能拿到什么 |
|---|---|---|
| 1 | `AVURLAsset -initWithURL:options:` | **URL + 请求头**（最理想） |
| 2 | `AVPlayerItem -initWithURL:automaticallyLoadedAssetKeys:` | 只有 URL |
| 3 | `AVPlayer -replaceCurrentItemWithPlayerItem:` | 从 asset 反查 URL |

**2. 为什么必须有本地代理，不能把地址直接给电视**

- 防盗链要 Referer
- m3u8 里的分片是**相对地址**，电视会按播放列表的 host 去拼；只代理主列表
  不代理分片，分片照样 403，还是黑屏
- 拖进度条要 `Range` 透传

代理必须**重写播放列表**，把三类 URI 全换成自己的地址（漏一种就是特定
片源必然失败）：裸分片行、`#EXT-X-KEY:URI="..."`、子播放列表。

**3. 为什么用悬浮按钮，而不是改它的播放器 UI**

宿主是纯 SwiftUI + 自绘播放器，类名被 strip，硬改视图层级要跟着它的版本
走、换个版本就白做。悬浮按钮是独立于宿主视图体系的，只要 App 在前台就在。

---

## 媒体流必须流式转发（一个真实的崩溃陷阱）

`NSURLSessionDataTask` 的 `completionHandler` 会把**整个响应体读进内存**。
整片 mp4 常见 200MB～2GB，在手机上直接 OOM 被系统杀掉。

症状：一投屏 App 就闪退，而日志里没有任何我们自己的错误——因为是系统杀的，
我们没机会记录。

所以代理用 `NSURLSessionDataDelegate` 流式转发：来一块转一块，
内存占用只跟块大小有关。

---

## 用到的门禁

四道，全部盯**产出物**而不是源码长相。

| 门禁 | 脚本 | 查什么 | 为什么不能省 |
|---|---|---|---|
| 1 | `verify_objc.py` | 括号配平、`@interface`/`@end` 配对、**跨文件**声明 vs 实现差集 | 纯搬运错误，编译前 2 秒就能抓，省 6 分钟 |
| 1' | `selftest_objc.py` | 8 个反向注入 | 证明上面那些断言**能失败** |
| 2 | `selftest_inject.py` | 18 项注入逻辑边界 | 注入改错一个偏移，产物"看起来正常"，装上去才崩 |
| 3 | `verify_dylib.py` | arm64 / iOS / `MH_DYLIB` / `__mod_init_func` 非空 / 类没被裁掉 | 编译成功 ≠ 产物可用 |
| 4 | `verify_ipa.py` | dylib 在包内且合法、`LC_LOAD_DYLIB` 存在、无残留签名、Info.plist 已补 | 前三道全绿也不代表最终 zip 里装的就是那个产物 |

门禁 4 单独存在的理由：UnCast 那次就是靠**产物差分**才发现某处修改
压根没进包——CI 全绿，装到设备上却没有那个行为。

---

## 构建

### CI（GitHub Actions，只需 macOS）

```bash
# 推上去就会跑，产出 kkcast-dylib 这个 artifact
git push origin main
```

CI 只编译 + 校验 dylib。**不打包 ipa**，原因很实际：原始 ipa 12MB，
base64 后 15.6MB，远超 GitHub Secret 的 48KB 上限；而且那是他人作品，
不该进公开仓库。

### 本机（注入 + 打包，纯 Python，不需要 macOS）

```bash
python scripts/build_ipa.py \
  --ipa /path/to/kkys-116.ipa \
  --dylib /path/to/KKCast.dylib \
  -o dist/kkys-dlna.ipa
```

脚本做六件事：解包 → 放 dylib → 补 `Info.plist` → 注入 `LC_LOAD_DYLIB`
→ 删旧签名 → 重打包，最后自检包里真的有东西。

注入策略是**就地插入**：`__TEXT` 段 header 后面有 7424 字节全零空隙，
把 `LC_LOAD_DYLIB`（72 字节）写进去，**不移动任何已有字节**，
所有 `vmaddr`/`fileoff` 保持不变。

如果空隙不够或不是全零，脚本会**拒绝执行**而不是硬写——
覆盖到 `__text` 的后果是 App 直接起不来，而且极难定位。

---

## 安装

产物是未签名 ipa。用 TrollStore 装（它会自动签名），或用你习惯的
重签工具签一次再装。

装完第一次打开会弹「本地网络」权限，**必须允许**。否则 SSDP 一个响应都
收不到，看起来像「电视不支持」。(`NSLocalNetworkUsageDescription`
已经在打包时补进去了，所以这个弹框会正常显示。)

---

## 怎么用

1. 手机和电视连同一个 WiFi
2. 在可可影视里正常开始播放一个片子
3. 右上角出现 📺 按钮，点它
4. 等 2～3 秒，列表里出现你的电视，点它
5. 电视开始播放；此时手机可以锁屏、可以切走

---

## 已知限制

- **只支持 http/https 源**。`file://` 是手机本地的下载文件，电视访问不到
  手机沙盒，跳过了。
- **只做推送，不做反向控制**。电视上按暂停/拖动不会同步回手机，
  手机上的进度也不控制电视。要双向同步得订阅 `AVTransport`
  的 GENA 事件，是另一套工作量。
- **不加入 SSDP 组播组**。用 `M-SEARCH` 单播收响应就够了，因为投屏是
  「用户点按钮才搜」。代价是看不到设备主动发的 NOTIFY——对投屏没影响，
  但做不了「设备上线自动出现在列表里」。
- **悬浮按钮位置固定右上角**。如果宿主的全屏播放器右上角有别的控件，
  可能视觉重叠。改 `KKCastUI.m` 里 `showButtonIfNeeded` 的 center 计算即可。
- **电视兼容性取决于电视**。老款电视对 `DIDL-Lite` 元数据挑剔，
  `protocolInfo` 里的 MIME 不对会拒绝加载。代码里按 `.m3u8` / `.mp4`
  给的是常见值。