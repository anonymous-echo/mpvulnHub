#  NodeJS 0day！代码安全为何重要 —突破强化的环境   
一个不正经的黑客  一个不正经的黑客   2024-10-10 22:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9JJYSsWUbBjw7BIQbPT8JOpTk1Pe8rQl7fSz9Kv2PMOqvymRoDBnn9Q/640?wx_fmt=png&from=appmsg "")  
  
基础设施强化能够使应用程序在面对攻击时更具韧性。  
  
这些安全措施提高了攻击者的入侵难度，给他们设置了更多的障碍。然而，这并非万能之策，因为决心坚定的攻击者依然可以通过源代码中的漏洞发起攻击。  
  
在本篇博文中，我们将通过展示一种攻击技术，强调基础代码安全的重要性。  
  
该技术展示了攻击者如何利用Node.js应用程序中的文件写入漏洞，实现远程代码执行——即便目标文件系统已被设置为只读模式。  
  
通过利用暴露的管道文件描述符，攻击者可以绕过在这种强化环境中施加的限制，从而获得代码执行权限。  
> 本篇博文的内容也已在Hexacon24大会上进行了展示。  
> 我们将在录制视频发布后添加链接，并会在X/Twitter和Mastodon平台上通知大家。  
  
### 文件写入漏洞  
  
在我们以Web为主的漏洞研究中，经常会遇到各种类型的漏洞，例如跨站脚本攻击（XSS）、SQL注入、不安全的反序列化、服务器端请求伪造（SSRF）等。  
  
虽然这些漏洞的影响和利用难度各不相同，但对于某些类型的漏洞，一旦被发现，几乎可以肯定整套应用程序都将面临被攻破的风险。  
  
其中一种关键的漏洞类型是任意文件写入漏洞。  
  
攻击者需要确定具体要写入什么文件、以及写入到何处，但通常存在许多方法可以将这一漏洞转化为代码执行，从而完全攻陷应用程序的服务器：  
- 将PHP、JSP、ASPX或类似的文件写入到Web根目录。  
  
- 覆盖由服务器端模板引擎处理的模板文件。  
  
- 写入配置文件（如uWSGI的.ini文件或Jetty的.xml文件）。  
  
- 添加Python的站点特定配置钩子。  
  
- 采用通用方法，例如写入SSH密钥，添加定时任务（cronjob），或覆盖用户的.bashrc文件。  
  
这些例子表明，攻击者通常能够轻松地将任意文件写入漏洞转化为代码执行。  
  
为了减少此类漏洞的危害，应用程序的底层基础设施往往会被强化——这虽然增加了攻击难度，但并不意味着攻击者无法加以利用  
### 突破强化环境  
  
我们最近在一个Node.js应用程序中发现了一个任意文件写入漏洞，虽然该漏洞的利用难度较高，但依然引发了我们的兴趣。  
  
漏洞本身较为复杂，但归根结底可简化为以下易受攻击的代码片段：  
```
app.post('/upload', (req, res) => {
   const { filename, content } = req.body;
   fs.writeFile(filename, content, () => {
       res.json({ message: 'File uploaded!' });
   });
});
```  
  
此处使用了 fs.writeFile函数来写入文件，而 filename和 content两个参数完全由用户控制。因此，这是一个典型的任意文件写入漏洞。  
  
在评估该漏洞的影响时，我们注意到运行应用程序的用户被限制为只能对特定的上传文件夹拥有写入权限。除此之外，整个文件系统都是只读的。尽管这看似使漏洞的利用陷入了困境，但这也引发了我们进一步的研究问题：  
  
即便目标文件系统已被挂载为只读模式，是否依然可以将任意文件写入漏洞转化为代码执行？  
### 只读文件写入  
  
在类似Linux的Unix系统中，万物皆文件。  
  
与传统的ext4文件系统不同，后者将数据存储在物理硬盘驱动器上，而一些其他类型的文件系统则用于不同的目的。  
  
其中之一是procfs虚拟文件系统，它通常挂载在 /proc目录，充当观察内核内部运作的窗口。  
  
procfs并不存储实际文件，而是提供对运行中的进程、系统内存、硬件配置等实时信息的访问。  
  
procfs提供的一项特别有趣的信息是运行进程的打开文件描述符，位于 /proc/<pid>/fd/目录下。  
  
进程打开的文件不仅仅是传统文件，还可能是设备文件、套接字和管道。例如，以下命令可以用于列出Node.js进程的打开文件描述符：  
```
ls -l /proc/<pid>/fd/
```  
```
  user@host:~$ ls -al /proc/`pidof node`/fd
  total 0
  dr-x------ 2 user user 22 Oct 8 13:37 .
  dr-xr-xr-x 9 user user  0 Oct 8 13:37 ..
  lrwx------ 1 user user 64 Oct 8 13:37 0 -> /dev/pts/1
  lrwx------ 1 user user 64 Oct 8 13:37 1 -> /dev/pts/1
  lrwx------ 1 user user 64 Oct 8 13:37 2 -> /dev/pts/1
  lrwx------ 1 user user 64 Oct 8 13:37 3 -> 'anon_inode:[eventpoll]'
  lr-x------ 1 user user 64 Oct 8 13:37 4 -> 'pipe:[9173261]'
  l-wx------ 1 user user 64 Oct 8 13:37 5 -> 'pipe:[9173261]'
  lr-x------ 1 user user 64 Oct 8 13:37 6 -> 'pipe:[9173262]'
  l-wx------ 1 user user 64 Oct 8 13:37 7 -> 'pipe:[9173262]'
  lrwx------ 1 user user 64 Oct 8 13:37 8 -> 'anon_inode:[eventfd]'
  lrwx------ 1 user user 64 Oct 8 13:37 9 -> 'anon_inode:[eventpoll]'
  ...
```  
  
正如上面的输出所示，打开的文件描述符中也包括匿名管道（例如 pipe:[9173261]）。  
  
与命名管道不同，匿名管道并不会在文件系统中作为具名文件暴露出来，因此通常无法直接写入匿名管道，因为缺乏引用。  
  
但procfs文件系统允许我们通过 /proc/<pid>/fd/目录中的条目引用该管道。  
  
与procfs中的其他文件不同，写入这个管道不需要root权限，运行Node.js应用程序的低权限用户就可以执行此操作：  
```
user@host:~$ echo hello > /proc/`pidof node`/fd/5
```  
  
即使在procfs挂载为只读的情况下（例如在Docker容器中），写入管道仍然是可能的，因为管道由一个名为pipefs的独立文件系统处理，该文件系统由内核内部使用。  
  
这为能够进行任意文件写入的攻击者揭示了新的攻击面，因为攻击者可以将数据传递给从匿名管道读取的事件处理程序。  
### Node.js与管道  
  
Node.js是基于V8 JavaScript引擎构建的，V8是单线程的。然而，Node.js提供了异步和非阻塞的事件循环。为了实现这一点，它使用了一个名为libuv的库。  
  
这个库利用匿名管道来信号化并处理事件，这些管道可以通过procfs进行访问，正如我们在上面的输出中所看到的。  
  
当一个Node.js应用程序存在文件写入漏洞时，攻击者没有任何障碍来写入这些管道，因为它们是由运行该应用程序的同一用户写入的。但写入管道的数据会发生什么呢？  
  
在审计相关的libuv源代码时，我们注意到一个名为 uv__signal_event的处理程序。它假设从管道中读取的数据是 uv__signal_msg_t类型的消息：  
```
static void uv__signal_event(uv_loop_t* loop,
                             uv__io_t* w,
                             unsigned int events) {
  uv__signal_msg_t* msg;
  // [...]

  do {
    r = read(loop->signal_pipefd[0], buf + bytes, sizeof(buf) - bytes);
    // [...]

    for (i = 0; i < end; i += sizeof(uv__signal_msg_t)) {
      msg = (uv__signal_msg_t*) (buf + i);
      // [...]
```  
  
uv__signal_msg_t数据结构仅包含两个成员，一个是句柄指针，一个是名为 signum的整数：  
```
typedef struct {
  uv_signal_t* handle;
  int signum;
} uv__signal_msg_t;
```  
  
uv_signal_t类型的 handle指针是 uv_signal_s数据结构的typedef，它包含一个特别有趣的成员—— signal_cb：  
```
struct uv_signal_s {
  UV_HANDLE_FIELDS
  uv_signal_cb signal_cb;
  int signum;
  // [...]
};
```  
  
其中， signal_cb是一个函数指针，用于存储回调函数的地址。  
  
如果两个数据结构中的 signum值匹配，事件处理程序稍后会调用这个回调函数。  
  
这个机制使得Node.js能够响应信号事件，通过回调函数处理特定的操作。  
  
这也为利用 uv__signal_event中的管道写入提供了潜在的攻击途径。  
  
攻击者可以通过控制写入管道的数据，使得 signum匹配，从而触发回调函数，执行恶意代码。  
```
// [...]
handle = msg->handle;

if (msg->signum == handle->signum) {
    assert(!(handle->flags & UV_HANDLE_CLOSING));
    handle->signal_cb(handle, handle->signum);
}
```  
  
上述代码片段展示了事件处理程序如何根据管道中读取的消息中的 signum来触发相应的回调函数。  
  
如果 signum匹配，且句柄没有被关闭，事件处理程序会调用 signal_cb回调函数来执行相应的操作。  
  
接下来，以下图示展示了事件处理程序期望的数据结构：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9agQSwCHQmKOicuur9uWEtTnP2zzqicHcwTlhTZwjWvCFQ3A6v2CGKt1Q/640?wx_fmt=png&from=appmsg "")  
  
这是一个对攻击者非常有利的局面：他们可以将任何数据写入管道，并且可以通过函数指针快速触发回调函数。  
  
事实上，这并不是我们首次发现这一问题。2023年8月8日，HackerOne发布了Seunghyun Lee的报告，他描述了一个不同的场景，在这个场景中，他能够利用Node.js程序中的打开文件描述符绕过任何基于模块或进程的权限——基本上是实现了沙箱逃逸。  
  
即便在他所描述的这一场景中——我们当时并未考虑到这个情况——这仍然不被视为一个安全漏洞，报告被关闭为“信息性”报告。  
  
这意味着我们在接下来部分中描述的技术仍然适用于最新版本的Node.js，而且在近期内这一情况可能不会发生变化。  
### 构建数据结构  
  
攻击者利用文件写入漏洞攻击事件处理程序的一般策略可能如下所示：  
- 向管道写入一个伪造的 uv_signal_s数据结构。  
  
- 将 signal_cb函数指针设置为他们希望调用的任意地址。  
  
- 向管道写入一个伪造的 uv__signal_msg_t数据结构。  
  
- 将 handle指针指向之前写入的 uv_signal_s数据结构。  
  
- 设置两个数据结构的 signum值相同。  
  
- 获得任意代码执行权限。  
  
假设攻击者只能写入文件，那么这一切必须通过一次性写入实现，且无法在此之前读取任何内存。  
  
事件处理程序的缓冲区相当大，这使得攻击者可以轻松地将这两个数据结构写入管道。然而，仍然存在一个障碍：数据结构的地址未知，因为所有写入管道的数据都存储在栈上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9EZ5ueT7FhCD7npkcEgXkicI45rmiasBhTCSicPEQPE2ZEs6Jiay9rSmL9w/640?wx_fmt=png&from=appmsg "")  
  
因此，攻击者无法使 handle指针引用伪造的 uv_signal_s数据结构。  
  
这就引出了一个问题：攻击者是否可以引用任何数据？  
  
栈、堆以及所有库的地址都通过ASLR（地址空间布局随机化）进行了随机化。  
  
然而，Node.js二进制文件本身的段并没有进行随机化。令我们惊讶的是，官方Linux版的Node.js并未启用PIE（位置独立可执行文件）：  
```
user@host:~$ checksec /opt/node-v22.9.0-linux-x64/bin/node
[*] '/opt/node-v22.9.0-linux-x64/bin/node'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```  
  
显然，未启用PIE是出于性能考虑，因为PIE的间接寻址会带来一些小的开销。  
  
对于攻击者来说，这意味着他们可以引用Node.js段中的数据，因为该地址是已知的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9CsiaYE6argcjxs7onKT0eEricP6cBET5uibBXOqw1muTuqeRgXyFFxmKg/640?wx_fmt=png&from=appmsg "")  
  
接下来的问题是：攻击者如何将伪造的 uv_signal_s数据结构存储在Node.js段中？  
  
一种方法是寻找使Node.js将攻击者控制的数据存储在静态位置（例如，从HTTP请求中读取的数据），但这似乎相当具有挑战性。  
  
一种更简单的方法是直接利用已经存在的资源。  
  
通过检查Node.js的内存段，攻击者可能能够识别出适合用作 uv_signal_s伪造结构的数据。  
  
攻击者理想中的数据结构可能类似于下面这样：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI99ozujDlX4UsZ6iae13icJF1mEl8at3DWFHlAlUgkDNzAppKCXzFSIghQ/640?wx_fmt=png&from=appmsg "")  
  
这个数据结构以一个命令字符串（"touch /tmp/pwned"）开始，后跟 system的地址，位于正确的偏移位置，以便与 signal_cb函数指针重叠。  
  
攻击者只需要使 signum值与伪造的 uv_signal_s数据结构匹配，这样回调函数就会被调用，从而有效地执行 system("touch /tmp/pwned")。  
  
这种方法要求 system的地址存在于Node.js的某个段中。  
  
通常，全球偏移表（GOT）是一个候选位置。  
  
然而，Node.js并未使用 system函数，因此它的地址不在GOT中。即使存在，伪造的 uv_signal_s数据结构的开始部分可能也是GOT中的另一个条目，而不是一个有用的命令字符串。因此，另一种方法似乎更具可行性：经典的ROP链（返回导向编程）。  
  
每个ROP链的开头都是寻找有用的ROP小工具（gadgets）。  
  
用于寻找ROP小工具的工具通常会解析磁盘上的ELF文件，然后确定所有可执行的段。.text段通常是最大的可执行段，因为它存储了程序本身的指令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9CUKdxlmGv01BCxA6MOF7KfnHqPEEshstKvR5HfgibWGrkkXicia2qxvqw/640?wx_fmt=png&from=appmsg "")  
  
现在，工具会遍历该段中的字节，寻找 ret指令，例如，因为这是ROP小工具的合适结束指令。接着，工具从表示 ret指令的字节开始，逐字节回溯，以确定所有可能有用的ROP小工具：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9yicLIdAEB4Zxm3ZlmtHn2USjVN29qU1DGz6fwdnzem62G2JRUfJ5y8w/640?wx_fmt=png&from=appmsg "")  
  
然而，在这种情况下，这并不是攻击者所需要的。攻击者并不需要一个ROP小工具，而是需要一个引用伪造 uv_signal_s数据结构的地址，该结构通过其 signal_cb函数指针引用一个ROP小工具。因此，存在一个间接引用：ROP小工具（即一段指令序列的地址）需要存储在被引用的数据中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9SN5rMnyrx0DI5Xn5p27iazicibCfGkyCiczZs1wxAd9LtpjHHgrmGYrRlg/640?wx_fmt=png&from=appmsg "")  
  
为了识别类似的合适数据结构，攻击者需要像传统的ROP小工具搜索工具一样，遍历Node.js镜像。  
  
不同之处在于，攻击者不仅对可执行的段（如 .text段）感兴趣。伪造的数据结构所在的内存不必是可执行的。  
  
攻击者需要的是指向小工具的指针。因此，他们可以考虑所有至少是可读的段。  
  
此外，这个搜索可以在内存中进行，而不仅仅是解析磁盘上的ELF文件。  
  
通过这种方式，攻击者还可以找到仅在运行时创建的数据结构，例如位于 .bss段中的结构。  
  
这可能会导致误报或依赖于特定环境的结构，但也增加了找到有用结果的机会，随后可通过手动验证。  
  
实现这种内存中伪造数据结构的基本搜索实际上非常简单：  
```
for addr, len in nodejs_segments:
   for offset in range(len - 7):
       ptr = read_mem(addr + offset, 8)
       if is_mapped(ptr) and is_executable(ptr):
           instr = read_mem(ptr, n)
           if is_useful_gadet(instr):
               print('gadget at %08x' % addr + offset)
               print('-> ' + disassemble(instr))
```  
  
这个Python脚本遍历所有Node.js的内存区域，每次将8个字节解释为一个指针，并尝试引用它。  
  
如果该地址被映射并且引用的是可执行段中的内存，它会判断该地址处存储的字节序列是否为有用的ROP小工具：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9SQaFC1nBrWnGTGhehAzDIJlPyl8HmicbGpVALXialkAdqUWCqYOCukxw/640?wx_fmt=png&from=appmsg "")  
  
这是Python脚本实际运行时的样子：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/cxf9lzscpMoTbKNoEMlgSXROl89twTI9ibSwSoaoPuqqHwX3P29Xft5Capzapjxf0j4atvI5Jiatreo4EGsI9yWg/640?wx_fmt=gif&from=appmsg "")  
  
所有潜在有用的ROP小工具都会输出，它们可以作为回调函数被调用时执行的第一个ROP小工具。  
  
由于写入管道的所有数据都存储在堆栈上，攻击者只需找到一个合适的堆栈指针跳转（stack pivoting）小工具即可。  
  
完成堆栈指针跳转后，攻击者就可以使用经典的ROP链来执行控制：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9G6DM97LiacQbgAS4xibkkGbaXYsurM0VpmR4icicDnDlOGQslIevRZgskQ/640?wx_fmt=png&from=appmsg "")  
  
使用该技术来利用任意文件写入漏洞时，仍然存在一个问题。  
  
通常，用于写入文件的函数（如本文中的 fs.writeFile）会限制写入的数据为有效的UTF-8编码。因此，写入管道的所有数据都必须是有效的UTF-8编码。  
### 克服UTF-8限制  
  
克服UTF-8限制  
  
由于Node.js二进制文件的体积非常大（最新的x64构建约为110M），因此找到与经典ROP链兼容的UTF-8小工具并不困难。然而，这一限制进一步缩小了现有数据中伪造 uv_signal_s数据结构的潜在合适数据结构。因此，需要在脚本中添加一个额外的检查，以验证伪造数据结构的基地址是否为有效的UTF-8编码：  
```
for addr, len in nodejs_segments:
    for offset in range(len - 7):
        if not is_valid_utf8(addr + offset - 0x60): 
            continue
        ptr = read_mem(addr + offset, 8)
        # [...]
```  
  
即使添加了这个额外的检查，脚本仍然会找到引用堆栈跳转小工具的合适伪造数据结构，例如：  
```
...
0x4354ca1 -> 0x12d0000: pop rsi; pop r15; pop rbp; ret
...
```  
  
这是相关数据结构在内存中的样子：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9My5t2rzdDLhRaZPb39VOkIPRtnx2GJAwH60en1SqwCnCozehNXM22A/640?wx_fmt=png&from=appmsg "")  
  
这个伪造数据结构的基地址（0x4354c41）是有效的UTF-8，因此 uv__signal_msg_t数据结构中的 handle指针可以正确填充。然而，另一个与UTF-8相关的问题出现在 signum值上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9Az7Q8V6p5QodO2OHxFYic87mibHFtHzoMicC9icW4Ea1aiclLUebk2ZRwoA/640?wx_fmt=png&from=appmsg "")  
  
signum值的最后一个字节是0xf0，而0xf0并不是有效的UTF-8编码。  
  
如果攻击者尝试通过文件写入漏洞写入这个字节，它将被替换为替换字符，从而导致 signum值的检查失败。  
  
如果我们在UTF-8可视化工具中输入0xf0，我们会看到这个字节引入了一个4字节的UTF-8序列：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9kSgGrkUHT0INjOt40B26ibnZH0MCkhoN4son5RPOehVyvEBtJdHE0aA/640?wx_fmt=png&from=appmsg "")  
  
因此，UTF-8解析器期望在这个字节后面紧跟3个延续字节。  
  
由于 uv__signal_msg_t数据结构包含一个8字节的指针和一个4字节的整数，编译器会添加4个额外的填充字节，以确保结构体的对齐是16字节对齐的。  
  
这些填充字节可以被用来插入3个有效的UTF-8延续字节，从而构造一个合法的4字节UTF-8序列。  
  
通过这种方式，攻击者可以有效绕过UTF-8的字节验证限制，创建一个看似合法的UTF-8编码数据结构，并使得数据结构能够正确解析。最终，攻击者能够利用这个构造好的伪造数据结构，执行目标代码，从而达到代码执行的目的。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/cxf9lzscpMoTbKNoEMlgSXROl89twTI9esz3BJh4Ge069AZO6QQIVHgYT19PugQibjnGOWDFPMNcYsQqx5PU8xw/640?wx_fmt=gif&from=appmsg "")  
  
例如，上述的软盘符号（💾）就是一个有效的4字节UTF-8序列，起始字节为0xf0。通过添加这些延续字节，攻击者可以满足整个有效载荷是有效UTF-8的要求，并确保两个 signum值匹配，从而使得伪造的数据结构能够被正确解析。这样，攻击者可以利用这一结构触发回调函数，进而执行恶意代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoTbKNoEMlgSXROl89twTI9Msx2DaZib5B4Kicnv05oXDwGrhLC4RuBCYCHEsGR2AVMhuOh33CVsk8A/640?wx_fmt=png&from=appmsg "")  
  
随着最后一个障碍的消除，攻击者能够获得远程代码执行权限。  
  
以下视频演示了针对这个易受攻击的示例应用程序的攻击，该应用程序在一个具有只读根文件系统和只读procfs的系统上以低权限用户身份运行：  
  
https://youtu.be/8FFsORk8snE  
### Related Blog Posts  
- Pretalx Vulnerabilities: How to get accepted at every conference  
  
- Parallel Code Security: The Challenge of Concurrency  
  
- Patches, Collisions, and Root Shells: A Pwn2Own Adventure  
  
### Thanks  
  
thanks for https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/  
  
带来了一次精彩的由NodeJS文件任意上传漏洞到RCE的精彩之旅！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/dO9nbKoGl3Hvah0IYAHJWV9xhVBN6uQY49MWrqgq4Xb1OG43wMSgwdL7ezvnh0FFFXgxxOnxWMNMKCzOxIVicuA/640?wx_fmt=gif "")  
  
点个  
在看你最好看  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xjqlh84uxOQcnm7g20rb1QJBu2TBOrdPibb0b62z3RQg06QcWK6yeiaEhmEfOdWPRoC8y4HhbvQZ78zMpLuT3ahA/640?wx_fmt=gif "")  
  
  
