#  7天如何从捡破烂到成功挖出一堆0day   
sekirolove  UKFC安全   2025-05-04 12:07  
  
这是一个在2月初就酝酿要写的博客，因为本人大三下处于关键的十字路口考虑升学or就业实习，时间紧迫，以及厂商迟迟未出补丁，故搁置良久，恰逢此刻已到新的人生阶段，并且看到近期厂商已经发了修复后的固件，突然想起，便写下此文  
  
时间线  
  
根据厂商的要求，在修补后的固件发布之前，我对该漏洞的细节进行了保密。现在新版本固件已发布，在此分享此次漏洞挖掘的经历（包括挖掘思路，仿真模拟等），希望能为各位师傅带来一些启发。  
  
（2025年春节伊始，为了能在之后的春招有竞争的优势，故开始独立着手挖掘一些具有生命周期的iot产品的漏洞）  
  
2025年2月初 先着手开始复现并挖掘一些远古iot产品漏洞，在不断的捡破烂中学习😓  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/DCAAOMBAs87JiaT57NbNZLLVrPvDhOCYRHOdsdQeyIUKibmgQcicGJZjib0E6WRJraU9TtPqJZicjDcibbIvjox2uRQA/640?wx_fmt=jpeg&from=appmsg "")  
  
2月5日，定位到dlink厂商的  
DIR-823X AX3000双频无线千兆路由  
> https://www.dlink.com.cn/home/product?id=3118  
  
  
（主要是点进官网就是这个产品，并且发现产品较新cve较少）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DCAAOMBAs87JiaT57NbNZLLVrPvDhOCYRx4xricDSvgGsCJwTbP7xZxyOHsm0jIPVcf9d4cib7ibAT5Y9ouMNmSgow/640?wx_fmt=png&from=appmsg "")  
  
2月5-10日   
在工作日同dlink国区电话及邮件沟通上报漏洞及解决措施，并同dlink美区做邮件沟通申报漏洞，得到许可在新固件修补并发布之后公开  
  
2月10日 预申报cve并提供了漏洞具体方案  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DCAAOMBAs87JiaT57NbNZLLVrPvDhOCYRopPKbdbNfdBicOWhyBenluMl9Nx8GMlr4U7l6chztBCBBpn9WYoup9Q/640?wx_fmt=png&from=appmsg "")  
  
此为上图对应的链接  
> https://gist.github.com/SekiroLove/a548a87bafec0d6c143072383098afdf  
  
  
后续  
 但比较遗憾的是直到最后我把这个经历模糊的写到简历上，并且一发入魂，成功去到我心仪的大厂后，也无人给我回复，并在最近看到有人申请了这个漏洞，且时间线在我写好poc并发邮件的时间线之后，可能是求职期间嘴瓢了，让别人知道并申报了，并且自己一没申请cve经验二没怎么上心，不过也无所谓了，分享一下挖掘的过程吧😀  
  
漏洞挖掘思路  
  
这个漏洞的成因本身是源于之前版本的修复不慎  
  
具体参考24年的的这个命令执行的cve-2024-39202  
> https://www.cve.org/CVERecord?id=CVE-2024-39202  
  
  
主要漏洞部分是  
涉及参数拼接的内容，由于该cve明确指出了过往版本没有对一些参数输入做过滤，而导致命令执行的危险，故最开始主要针对这一点进行研究与深挖，发现最新版本20240802版本加设了对应的过滤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DCAAOMBAs87JiaT57NbNZLLVrPvDhOCYRAgyDZ752S5pHxGjxlb1UEoKEh2Df2le9fOL4exleo4NPhFariay23Zw/640?wx_fmt=png&from=appmsg "")  
  
但以一个pwn人常年打ctf的赛棍经验来说，这远远不够，拼接符“&”和“|”的未过滤导致了这依旧存在漏洞的隐患，故针对性的对每一个有隐患的漏洞构造poc即可  
  
之后占小部分的漏洞是  
一些藏在功能函数子函数的popen的漏洞，这个就不说了，厂商未作任何过滤，一个分号即可命令执行（  
这可能也是研发和安全之间存在的割裂吧，毕竟只要写出来功能就行了 ，没必要考虑那么多所谓的安全隐患，而安全人员要擦的屁股可就多了😋  
  
到了这里之后基本就比较简单了，能够成功仿真后，摸清交互便可成功命令执行  
  
仿真复现  
  
提取固件很简单 binwalk即可 未作任何加密  
  
#   
QEMU仿真  
  
仿真的过程基本都是围绕报错做对应patch，根据init的话，其中主要的服务位于/usr/sbin/goahead  
  
对于这个路由固件，  
在qemu仿真过程中注意该二进制文件正常启动服务需要****新建一个名为 “br-lan” 的网卡  
```
sudo brctl addbr br0
sudo ifconfig br0 ip
```  
  
方可正确打开服务，打开残缺路由login网页,此时即可进行漏洞挖掘  
  
#  
 系统仿真  
  
拿openwrt刷底包  
```
sudo qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a57 \
    -smp 4 \
    -m 512M \
    -kernel /home/sekiro/pwnTest/IoTsec/dlink/DIR-823X/openwrt-23.05.5-armsr-armv8-generic-kernel.bin \
    -initrd /home/sekiro/pwnTest/IoTsec/dlink/DIR-823X/openwrt-23.05.5-armsr-armv8-rootfs.cpio \
    -nographic \
    -append "root=/dev/ram rw console=ttyAMA0" \
    -net nic \
    -net tap,ifname=tap0,script=no,downscript=no
```  
  
再进行网络配置 方便虚拟机/wsl和 qemu 进行通信  
  
添加一个虚拟网卡，并为添加的虚拟网卡配置 IP 地址，这块就不再赘述了，网上资料以及ai都能很方便的解决  
  
此时需要把解包后的官方镜像打包传输到qemu  
```
scp rootfs.tar.gz root@*.*.*.*:/root/rootfs
tar zxvf rootfs.tar.gz
```  
  
再chroot启动，从执行init文件开始，这样的方式基本就可以启动一个完整的路由器服务  
  
需要更多的功能的话应该还得对于去patch，不过由于我们只是做漏洞挖掘复现，这些便已绰绰有余  
  
#  
 复现成功后  
  
由于该路由主要功能都集中在授权后，故需在第一次登录后进行对应授权认证，满足正确的session_id, auth_token方可进入常规功能，具体脚本已在后文链接中，此处不做赘述。  
  
(这块的内容由于时间原因已记忆模糊，有任何错误请随时指出)  
  
POC及漏洞复现  
  
声明：本文仅供用于安全技术的交流与学习，下文poc及demo仅适用于本地实验场景，若读者将本文内容用作其他用途，由读者承担全部法律及连带责任，文章作者不承担任何法律及连带责任。  
  
具体漏洞利用链不做更多阐述，由于篇幅问题等，复现demo等均在下文链接，其中涉及30个组件的漏洞  
仅可作本地复现用途  
> https://gist.github.com/SekiroLove/a548a87bafec0d6c143072383098afdf  
  
  
由于官方已经下架了去年的漏洞固件版本，故在此提供相应下架链接，  
仅作复现学习需求，其他行为本人概不负责  
> https://github.com/SekiroLove/IoT/blob/main/Firmwares/firmware-240802.bin  
  
  
后记  
  
感觉一切都是这么巧合，尽管从时间线来看，发邮件，漏洞及poc链接来说，都比其他人至少快1周，但最后也比较遗憾没有拿到cve（暂时。。。），但看了一下好像评分还挺高，但事实上这只是个授权的漏洞罢了，真在真实场景实用价值并不高，过程和后续影响似乎更重要一些🥺  
  
也幸好进入了新的人生阶段了，单纯的  
“这种连固件都不买就能挖到cve”的iot的生涯也早早收手结束，无论如何都算有所收获，给了我进入宇宙厂的筹码和实践检验，也算给这3个月前的经历画个句号😶‍🌫️  
  
之后就是转战下到底层硬件上到常规app安全全方位的系统安全领域了  
"Hope it goes dope, yo!"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DCAAOMBAs87JiaT57NbNZLLVrPvDhOCYRXTMoGvWgPcIN5iaaU56BO00xTz9bg4F95BgzKOYiap45NXa4h3Otkjyw/640?wx_fmt=png&from=appmsg "")  
  
peace~  
  
Q.E.D.  
  
