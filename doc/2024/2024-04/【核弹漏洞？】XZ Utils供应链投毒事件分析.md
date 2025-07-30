#  【核弹漏洞？】XZ Utils供应链投毒事件分析   
 船山信安   2024-04-01 00:00  
  
**事件描述**  
  
简单来说这是一起供应链投毒事件，攻击者通过上游开源项目投毒，最终随着项目集成影响 Linux 发行版，包括 Fedora Linux 40/41 等操作系统已经确认受该问题影响。  
  
2024年3月29日，微软PostgreSQL开发人员Andres Freund在调查SSH性能问题时，发现了XZ Utils软件包存在一系列异常行为，并将其分析结果发布到开源安全邮件列表(openwall)。他指出，在XZ Utils软件包中存在着一个涉及混淆恶意代码的供应链攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5y47kt1pRVlpFFYdIwnuWzuBavpWt7E6N6vXQVJVsDaMX3LZJqvxh36bsibbWZJPFsxXHz2Kia6urvw/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
目前发现受到影响的库版本有XZ Utils 和 liblzma 的5.6.0~5.6.1 版本。受其牵连的包含以下软件：  
  
Alpine Edge  
  
Arch  
  
Cygwin  
  
Exherbo  
  
Gentoo  
  
Homebrew  
  
KaOS  
  
MacPorts  
  
Manjaro Testing  
  
NixOS Unstable/nixpkgs unstable  
  
OpenIndiana  
  
OpenMamba  
  
OpenMandriva Rolling  
  
Parabola  
  
PCLinuxOS  
  
Pisi Linux  
  
pkgsrc current  
  
Ravenports  
  
Slackware current  
  
Solus  
  
Termux  
  
Wikidata  
  
  
企业使用的主流Linux发行版（Red Hat/CentOS/Debian/Ubuntu）的Stable稳定版仓库中尚未合并该存在后门的软件版本，因此受影响范围并没有快速扩大。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qcuWhlEY4HVy0g9ibI8QBDGPibgp47dGk1OTos9iabu2nJN1cF4uKfk4jNqhe5IS2Tywf7iaianO6ibVER0zTpyj5bA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
**事件经过**  
  
  
攻击者 JiaT75 (Jia Tan) 于 2021 年注册了 GitHub 账号，之后积极参与 XZ Utils 项目的维护，并逐渐获取信任，获得了直接 commit 代码的权利。  
  
  
JiaT75 在最近几个月的一次 commit 中，悄悄加入了 bad-3-corrupt_lzma2.xz 和 good-large_compressed.lzma 两个暗藏恶意代码的伪造二进制测试文件，然而在编译脚本中，在特定条件下会从这两个文件中读取内容对编译结果进行修改，致使编译结果和公开的源代码不一致。  
  
  
2024年3月29日，微软PostgreSQL开发人员Andres Freund在调查SSH性能问题时，发现了这个问题并报告给 oss-security，致使此次软件供应链攻击事件被披露。  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5y47kt1pRVlpFFYdIwnuWzuLowS4HWKHLeuJrTucfApopCcUnbCEXLLNSrv3ryXb491lYgrVEicF7A/640?wx_fmt=gif&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**处置建议**  
  
  
通过在命令行输入 xz --version 来检查 XZ Utils 版本，如果输出为 5.6.0 或 5.6.1 ，说明您的系统可能已被植入后门。  
  
如果相关版本在受影响范围内，利用如下自查脚本排查是否存在后门：  
```
#! /bin/bash
set -eu
# find path to liblzma used by sshd
path="$(ldd $(which sshd) | grep liblzma | grep -o '/[^ ]*')"
# does it even exist?
if [ "$path" == "" ]
Then
echo probably not vulnerable
Exit
fi
# check for function signature
if hexdump -ve '1/1 "%.2x"' "$path" | grep -q f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410
Then
echo probably vulnerableelseecho probably not vulnerable
fi
```  
  
  
若确认受影响，请将XZ Utils降级至 5.4.6 版本，或者更新至最新版本5.6.4。命令如下：  
  
  
sudo apt install xz-utils={要安装的目标版本}。  
  
  
  
