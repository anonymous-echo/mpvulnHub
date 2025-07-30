#  pwndbg：一款专为安全漏洞分析设计的GDB插件   
Alpha_h4ck  FreeBuf   2025-01-27 10:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于pwndbg**  
  
  
## pwndbg是一款专为安全漏洞分析设计的GDB插件，该工具可以大大简化研究人员使用GDB进行漏洞分析和调试的难度，该工具主要关注的是软件开发人员、硬件黑客、逆向工程师和漏洞分析人员所需的功能。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AADZSHbG9lDZZPuHDH7FqQfF8ATibb1hLLuCicrhTJkN9HQKpLqjDcPCA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
原始 GDB 不适合用于逆向工程和漏洞开发。输入x/g30x $esp并不好玩，而且无法提供太多信息。因此，pwndbg便应运而生。  
  
  
pwndbg是一个直接加载到 GDB 中的 Python 模块，它提供了一套实用程序和辅助工具来解决 GDB 中的所有问题并消除粗糙的边缘。  
  
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/pwndbg/pwndbg.git
```  
  
  
然后切换到项目目录中，使用工具提供的安装脚本完成pwndbg的安装：  
```
cd pwndbg

./setup.sh
```  
  
或者使用下列命令从项目源代码构建最新版本的pwndbg：  
```
cd <gdb-sources-dir>

mkdir build && cd build

sudo apt install libgmp-dev libmpfr-dev libreadline-dev texinfo  # required by build

../configure --disable-nls --disable-werror --with-system-readline --with-python=`which python3` --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all

make -j7
```  
###   
### 发布版本安装  
  
  
我们还可以直接访问该项目的  
Releases页面  
针对对应的系统架构版本（x86_64、armv7l、aarch64、riscv64）下载预编译的pwndbg版本。  
###   
### 其他安装  
  
  
基于 RPM 的系统上安装 (CentOS/Alma/Rocky/RHEL)：  
  
dnf install ./pwndbg-2024.08.29.x86_64.rpm  
  
# pwndbg  
  
  
基于 DEB 的系统 (Debian/Ubuntu/Kali) 上的安装：  
```
apt install ./pwndbg_2024.08.29_amd64.deb

# pwndbg
```  
```
```  
  
在 Alpine 上安装：  
```
apk add --allow-untrusted ./pwndbg_2024.08.29_x86_64.apk

# pwndbg
```  
```
```  
  
在 Arch Linux 上安装：  
```
pacman -U ./pwndbg-2024.08.29-1-x86_64.pkg.tar.zst

# pwndbg
```  
```
```  
  
通用 Linux 安装：  
```
tar -v -xf ./pwndbg_2024.08.29_amd64.tar.xz

# ./pwndbg/bin/pwndbg
```  
##   
  
**工具运行演示**  
  
  
## 工具配置  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AVgEa2ICHle98aY6JfaP7kjnB43ico2sQdzs7lJB6yjss0lrcM45TOwg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 上下文查看  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73A9WqGQ3oLhQ0030deZU8lxHzDYBCWVOcao3qH5z4iaCww4FYM8ozGFzQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 堆内存审计  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AXvElaAsjnLictqZlm08iaGdHicFqKbGyUI3kmejy1PVlAh9xdWH9pMujQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 泄露数据识别  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AlLcI6UicJbyn8NzEfcNktamVBT7xXZyWjXyASd2pu8cicCwQ1qcFazHQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### IDA Pro集成  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73AhSQQYsqK9rTA5ia1PxSKGZNxXOsam2ew33BjcbgjCkQFxn1VibTgSlVw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 信息搜索  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icnU7Ne7Md6I3ObAZDzic73ALdkbTibZOJicEjauyxfGsneHKcRLB6STM0BIqtN97hAQibvDMpSBn9dwQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**pwndbg**：  
  
  
https://github.com/pwndbg/pwndbg  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
