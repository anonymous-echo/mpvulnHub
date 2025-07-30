#  Linux内核漏洞分析系列——指定版本内核编译及使用   
bwner  看雪学苑   2023-05-18 17:59  
  
```
```  
  
  
调试内核漏洞时需要搭建调试环境，经常到处搜命令，或者是忘记了哪个流程然后临时使用搜索引擎，难成体系。因此在此处进行记录，把编译内核过程梳理一下，后续遇到什么问题再接着补充。  
  
  
```
```  
  
  
首先通过  
内核下载地址  
下载内核源码，下面做了一张图主要介绍一下官网主页上下载包带的各个参数含义。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLaib7BrD4qZic9GGwztTgGBDbbiaYTMicJOo4p8Ob9SpXDRpJCibqYW54vpw/640?wx_fmt=other "")  
  
   
  
通过log页面，可以搜索指定的版本进行下载。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLesBVsgBotibRsdd4FibTXKzvzgRU2icVjpodUVcLccgJ7RGibqMrLfPgiaw/640?wx_fmt=png "")  
  
  
```
```  
##   
## docker与VM编译内核对比  
  
  
docker消耗资源少，部署和迁移方便，VM隔离性更强。总的来说docker和VM的编译流程没有太大区别，因为我习惯在VM环境下进行操作，因此下文的编译流程都是在VMware17 Pro中进行操作的。  
  
## 编译流程  
  
  
我是在VMware中编译内核，步骤如下：  
  
  
1.创建一个虚拟机并安装操作系统。（此处使用的是ubuntu 20）  
  
  
```
```  
  
  
  
2.下载并解压内核源代码。（此处使用的是  
5.16.12  
）  
  
  
3.打开终端并切换到内核源代码目录。  
  
  
4.运行以下命令以配置内核：  
  
(1)make menuconfig  
  
```
```  
  
  
  
(2)make -j$(nproc)  
  
```
```  
  
  
  
(3)sudo make modules_install #将编译生成的内核模块复制到指定的系统目录中，以供内核使用  
  
```
```  
  
  
  
(4)dpkg --list | grep linux-image #列出已安装内核版本  
  
```
```  
  
  
  
(5)vim /etc/default/grub #修改默认启动的内核版本  
  
```
```  
  
  
  
(6)reboot  
  
## 编译报错及解决方案  
  
  
◆运行sudo make modules_install  
报错：  
  
```
```  
  
  
  
解决方案：  
  
```
```  
  
  
  
◆运行sudo make modules_install  
报错：  
```
$ sudo make modules_install
sed: can't read modules.order: No such file or directory
make: *** [Makefile:1479: __modinst_pre] Error 2
```  
  
  
解决方案：  
```
sudo depmod
sudo make modules_prepare
```  
  
  
  
◆使用make -j4  
后报错：  
```
make[1]: *** No rule to make target 'debian/canonical-certs.pem', needed by 'certs/x509_certificate_list'. Stop.
```  
  
  
解决方案：  
  
```
```  
  
  
  
◆使用make -j4  
后报错：  
```
BTF: .tmp_vmlinux.btf: pahole (pahole) is not available Failed to generate BTF for vmlinux Try to disable CONFIG_DEBUG_INFO_BTF make: *** [Makefile:1161: vmlinux] Error 1
```  
  
  
解决方案：  
```
(1) BTF（BPF Type Format）提供了一种可以在运行时访问内核类型信息的方法，允许编写运行在内核空间中的工具和程序来进行调试、性能分析和安全审计等操作，`make menuconfig`，然后在配置界面中找到“Kernel hacking”选项，找到“Compile-time checks and compiler options”，然后禁用“Compile the kernel with BTF type information”，保存退出。【这种是暴力方法，遇到报错就修改config，后续可能会遇到一些问题】
(2) sudo apt-get install dwarves
BTF报错一般是系统缺少dwarves软件包导致，因此安装软件包
```  
  
  
◆使用make -j4  
后报错：  
```
zstd: not found
```  
  
  
解决方案：  
```
sudo apt-get install zstd
zstd是一种用于数据压缩的快速压缩算法，可以用于将单个文件压缩成单个文件或将多个文件压缩成一个文件。与zip不同，zstd不包括任何目录结构，仅用于对数据进行压缩,
这个错误提示是因为编译内核时缺少zstd压缩库，内核编译时会使用到这个工具，所以需要apt安装。
```  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLVEggnHTCna68rqkRq5gNHnObiayibuQU6fk95icNGkov5NsotSBXfhiabQ/640?wx_fmt=png "")  
  
   
  
sudo make install  
运行成功后，此时通过dpkg --list | grep linux-image  
也看不到最新的5.16.12，因为我们需要选择重启选择新内核。此处可以进入GRUB或者修改配置文件设置。  
  
## 进入GRUB设置启动内核  
  
  
VMware下重启，长按shift，选择Advanced options或者Advanced选项，进入内核选项页面。（如果Ubuntu安装只有一个内核版本，则不会出现GRUB菜单，虚拟机将直接启动Ubuntu。）  
  
   
  
进入GRUB：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLYx59YkCGQjmelD5taynWBW4PbxN9Hlafl9diajgAD0tK8kjdENJc2Gg/640?wx_fmt=png "")  
  
   
  
进入Advanced options，选择第一个:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLzjEia8f2hBkIDM7zAB00qOY33cEoPiaMNNNwB6vFzd9tDeFRvm9VibZxQ/640?wx_fmt=png "")  
  
   
  
切换内核成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZLiaiaBZy8pkYlpSD8RjXIxftemkQc6wfJoLaZiamjxvjSRxlgUu5SiajZYA/640?wx_fmt=png "")  
  
  
```
```  
  
  
本文主要是对内核编译的整体流程进行一个梳理，针对编译流程中进行记录，后续对内核漏洞进行复现与分析。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EOsxCcRWRvI4Ez7sZjkGZL0KgG4EWkmiacqeaMFUl6RF2PmqIdDEB3vGibJgppQsAf9BRicMMjicImbQ/640?wx_fmt=png "")  
  
  
**看雪ID：bwner**  
  
https://bbs.kanxue.com/user-home-951654.htm  
  
*本文  
为看雪论坛优秀文章，由看雪论坛 bwner 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[针对Model X无钥匙系统的远程攻击](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504553&idx=1&sn=2a6304e7f701cf21e164828629c84e2f&chksm=b18efde386f974f5afa8a7171bac1d61198b5db4cef45a4c8379825d6a6f236edb183676c44c&scene=21#wechat_redirect)  
  
  
2、[CVE-2023-21768 Windows内核提权漏洞](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504523&idx=1&sn=efa8d1d5a282655cfd12dfbf973a3c12&chksm=b18efdc186f974d78d20a6e7ed6a29099ff6664fb96a58de72172bd73f87b08f7ae0c248dd2a&scene=21#wechat_redirect)  
  
  
3、[贵阳大数据及网络安全精英对抗赛Reverse EZRE_0解题](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504494&idx=1&sn=2a76d7229f72d3aa2333ffdeaa7621ea&chksm=b18efda486f974b2a7fa1d5b94664c52c3a2052dbe68c441db8767c7ba6439a29abb7221beb4&scene=21#wechat_redirect)  
  
  
4、[Pwndbg+tmux真乃天作之合](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504430&idx=1&sn=ecde655b0ec414546b288772c30823cb&chksm=b18efc6486f975727b952b505733d3c70be7b2acbdd72cdbeee6003177cdbe303269b9bbbe9c&scene=21#wechat_redirect)  
  
  
5、[程序隐藏、加壳、内存加载运行的一种实验](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504429&idx=1&sn=412e435de040df0b0b439537d2958e68&chksm=b18efc6786f975717f7bd73b6b57cf4ef2b6f1b394ce5631930320270bf6f3b74b179b02b1d6&scene=21#wechat_redirect)  
  
  
6、[腾讯游戏安全大赛初赛题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458504400&idx=1&sn=c313b7e7a843a7e9ccc2de4ba62c88a3&chksm=b18efc5a86f9754c8c7efaf66edfea7c1cd8b5522334768164e8d40010c43dc29015388bde35&scene=21#wechat_redirect)  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
