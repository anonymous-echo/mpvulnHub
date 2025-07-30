#  在Windows强跑Docker，8GB内存都喂不饱漏洞扫描神器？   
原创 衡水铁头哥  铁军哥   2025-05-29 23:45  
  
我们前面已经在Windows系统上安装好了Docker桌面版  
（[Windows也能玩转Docker！手把手教你部署Redroid云手机](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860580&idx=1&sn=c038284c0081dbfa540f2196c2be6f76&scene=21#wechat_redirect)  
  
），运行效果挺勉强的，毕竟上来就选了一个难度超高的云手机项目  
（[高性能游戏云手机革命！GPU加速让Redroid性能追平小米15](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860530&idx=1&sn=4f8d8d70812910fcbd0b06ab0c67c6d7&scene=21#wechat_redirect)  
  
）。在Linux系统运行时，内核加载还方便一些，但是换到Windows系统，操作可真是太复杂了，网上有方法，感兴趣的小伙伴自己去搜一下。  
  
当然，在Windows系统中运行Docker的资源利用率也是真低，毕竟臃肿的Windows系统，加上Hyper-V嵌套虚拟化，轻轻松松吃掉5 GB运行内存稀松平常；相比于直接使用Linux系统而言，好几个GB的内存就这么白白浪费了，而且镜像读写都满。没办法，毕竟人力效率跟资源效率不能兼顾。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6ysm6G19Vgr1Q2Vpiaw1YKxgSTLXstz3kRSm4g9Sb1zahHTiaBib48sHhg/640?wx_fmt=png "")  
  
在很久很久之前，我们写过一篇如何对主机进行安全防护的文章  
（[主机安全漏洞解决方案](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458839193&idx=1&sn=3cc8f6611513d2554d624bdec1b2a6d1&scene=21#wechat_redirect)  
  
），里面介绍了如何进行系统扫描，当时是用的H3C的漏扫工具。后来也介绍过Nessus  
（[Linux环境部署Nessus扫描工具](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458840369&idx=1&sn=164d28bcc3dc0c68403fe89eaae2b37a&scene=21#wechat_redirect)  
  
），最近听说从Nessus分出来的开源版本OpenVAS还不错，今天简单尝试一下。  
  
OpenVAS是支持以Docker形式部署的，我们直接在镜像库中搜索即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6jZ0mkCJZKkZ6KmVHV9pO8N6UNyaYjAO8n8Ulo978jwedqWNsjLJXzQ/640?wx_fmt=png "")  
  
搜索结果一大堆，下载量破千万的mikesplain/openvas竟然不是第一个，而OpenVAS的官方是Greenbone，竟然没有出现在搜索结果里面。我们换成greenbone/openvas试一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6LyDzaapTboQNlcsyic4OwO54u4TZFfY1TdEUYmdKLxvxs5OsHibEuHxw/640?wx_fmt=png "")  
  
确实有官方的镜像，但是下载量都比较低，还区分了好几个版本。搜了一下，说是greenbone/openvas采用模块化设计，支持与Redis、PostgreSQL等组件协同工作，可扩展为多容器生产级部署，部署稍微复杂一些，并且可能需要付费；而mikesplain/openvas定位为“开箱即用”的快速部署方案，整合了Web界面  
GSA（Greenbone Security Assistant）和扫描引擎，开源免费，适合个人测试或小型环境，缺点就是更新频率较低，使用较旧的开源社区漏洞库。  
  
如果是简单测试的话，我们先试一下mikesplain/openvas吧，可以通过标签选择镜像版本，初次使用，就选latest吧。点击【Pull】下载镜像，或者直接点击【Run】运行容器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6PK6OYAFcPO4lIwyHG9jzhrBcZVa6uayKyKzYWhYibPlU36oeOtXkIWw/640?wx_fmt=png "")  
  
在本地镜像这里，能看到镜像的下载进度。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6fgHROA1MqhgXklCdqL4543b7DneiaMN0Ck5OSriaLgEauv36RLEF7WibQ/640?wx_fmt=png "")  
  
该说不说，Docker桌面版的效率确实有点低，加载镜像耗时比Linux系统下要多好几倍。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6l3cBJh2TPOFOP1VbfLZiaUicmYpicyFjp6eCHbJIbmeLDOJXQKp0mGicVA/640?wx_fmt=png "")  
  
意外的是，最新版本是6年前的，失敬失敬。点击运行按钮之后，在端口这里，我们需要将容器使用的TCP端口443和9390两个端口映射出来，要不然无法访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6PZPz70zN2TibZmERiaPvTyRKstaFM3cd6xfZxDZicwUFSAs2G6kRsic0SA/640?wx_fmt=png "")  
  
容器运行之后，我们可以在Inspect一栏查看容器的详细信息（）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6nr6xic2Md9WFKyKmgLo1tQRN0d6U3Uh1qXUHLD5g4ISj8qibQd8cANSg/640?wx_fmt=png "")  
  
可以看到，容器分配的IP地址为172.17.0.2，网关为172.17.0.1。这个网关在哪里呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6LwSV7w4xcA13b4cBiarZOic6Km1SYicbxlFDLee4icWk4ztLSe6ADicP4gw/640?wx_fmt=png "")  
  
可以看到，我现在电脑一共有6张网卡，其中Ethernet0是本地网卡，IP地址是192.168.1.52；VMnet1和VMnet8是VMware Workstation的虚拟网卡  
（[网络之路15：认识虚拟化环境VMware ESXi](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458851229&idx=1&sn=8bd6637fdf7937be534ef44e4569b67a&scene=21#wechat_redirect)  
  
）；最后一个TAP网卡是VPN创建的虚拟网卡。  
  
那就还剩下两张vEthernet网卡。一张备注为Default Switch，应该是Hyper-V的虚拟交换机绑定的网卡  
（[能找到Hyper-V和VMware共存的方法吗？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458856662&idx=1&sn=287527e355b0ca6b3c4350862d6a0801&scene=21#wechat_redirect)  
  
），IP地址为172.20.128.1/20。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6H3vyNbtCicdkjMnGLyNsEpwBcgKEOaC8MHx2icWvXqEaJpzDKibXGPYZw/640?wx_fmt=png "")  
  
另一张备注为WSL  
（[在Windows 11上启用WSL（适用于Linux的Windows子系统）](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859136&idx=1&sn=5e5c3f500d59065cbb500270bfae9133&scene=21#wechat_redirect)  
  
），IP地址为172.20.208.1/20，Docker容器应该是跑在这张网卡上的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6eS2ECm75hWZR6M1g9cSmHjyiaiaLYhIkqSpfL6BVHBcXeicNib0meyC39g/640?wx_fmt=png "")  
  
查看WSL状态，竟然有两台虚拟机在运行，分别是Ubuntu-24.04和docker-desktop。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6cqYv5qIk3FVXibEvkmoN37XNv8NcJTnmyjl8yvPJ6wcnpQ52OmpaTkA/640?wx_fmt=png "")  
  
这个docker-desktop是运行Docker容器使用的，那Ubuntu-24.04怎么还运行起来了？  
  
我们先进到docker-desktop中看一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY65f0RMsfOz9gCBNSpEzsKkRNOUQqtdmicVnfwYTVSLmmQUOhSfniagzUw/640?wx_fmt=png "")  
  
可以看到，虚拟机只有一张网卡，IP地址为172.22.213.185/20，网关是172.22.208.1，也就是系统中备注为WSL的vEthernet网卡。但是，没有看到docker0那张桥接网卡。  
  
那我们再切换到Ubuntu-24.04看一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6BdrhXpNLYGbLh5091M0bDfYkGbo5AbnwGJ0syGric15bH2xTt75qibXA/640?wx_fmt=png "")  
  
巧了，两个虚拟机用的一个IP地址，MAC地址也是一样的，难道这是同一个虚拟机？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6rsReTQ9FIlBgbVyD3zLQexkmNqaVic1KXHoKKiaJicg4mcyKoWl0uz6Dg/640?wx_fmt=png "")  
  
从虚拟机里面到172.17.0.2不通，但是到172.17.0.1能通，TTL为63，说明还不是直连的。回到宿主机看一下，发现到172.17.0.1的TTL为64，说明是直连的，但是我没有找到这个网卡。到172.17.0.2不通，应该是容器的安全策略问题了。  
  
Docker桌面版的展示还挺多，能查看CPU、内存、磁盘读写和网络使用情况。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6kQw9ahSHZ1DHvVyRS3HcQsyseeLrkb4aeJZLibFE1xQ3hS0SwPV6KSw/640?wx_fmt=png "")  
  
如果点容器上面的端口映射，会自动打开对应的页面，但是我们需要将其修改为HTTPS协议。当我尝试使用默认的localhost访问时，提示拒绝访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6wq6ydQMeYFfRxs94kTuO3macgaClnm8YicjERJQr2wlXdiaKZm6XdTqg/640?wx_fmt=png "")  
  
如果换成IP地址+端口进行访问，则提示  
GSA（Greenbone Security Assistant）校验失败。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6JveD4ibeHhqvIx8xMiaCWn0XwFPIu5rXHIxrt4GibHMphp0lJXKg8uUwQ/640?wx_fmt=png "")  
  
简单总结一下，Docker桌面版是真不好用啊。图形化界面可配置参数比较少，运行慢，资源占用率还高。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM5jdliajgSQEiaZgZ49XwlicY6wNjIYLtYnKAvVAyg8MMIwbBic8FzOMVO1qI1DwmfmA0xAO1z0lkMVEA/640?wx_fmt=png "")  
  
不说了，我去换到Ubuntu上试一下。  
  
  
**推荐阅读***  
  
[告别ADB！用DHCP选项让手机自动添加静态路由](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860514&idx=1&sn=c127b47f41e0d02b9dab6806ad72c4ad&scene=21#wechat_redirect)  
  
  
[Windows也能玩转Docker！手把手教你部署Redroid云手机](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860580&idx=1&sn=c038284c0081dbfa540f2196c2be6f76&scene=21#wechat_redirect)  
  
  
[高性能游戏云手机革命！GPU加速让Redroid性能追平小米15](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860530&idx=1&sn=4f8d8d70812910fcbd0b06ab0c67c6d7&scene=21#wechat_redirect)  
  
  
[1条命令搞定！Ubuntu搭建L2TP服务器全自动脚本，小白也能轻松上手](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860388&idx=1&sn=ce69376231385a35495af4f7fbacbc4b&scene=21#wechat_redirect)  
  
  
[免费日志分析神器Panalog实战：从安装到对接华三设备](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860556&idx=1&sn=df72ddd289dc7a773b2dae46407d0c8c&scene=21#wechat_redirect)  
  
  
[插上U盘自动装系统？一文掌握Ubuntu服务器版自动安装镜像制作](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860448&idx=1&sn=d833cc7414ffcec71297ae6bdbbea30b&scene=21#wechat_redirect)  
  
  
[连WiFi就能切IP！揭秘企业级路由器多VPN出口黑科技！](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860446&idx=1&sn=d148fbab56322f0bba7718cd01f7a718&scene=21#wechat_redirect)  
  
  
[云手机全球落地实战：用策略路由实现Docker容器网络自由切换](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860475&idx=1&sn=72dfa0a56b4933983a556344dbea9013&scene=21#wechat_redirect)  
  
  
[VMware Edge 620神操作：刷入iStoreOS秒变全能企业级网关，轻松玩转多SSID](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860498&idx=1&sn=a7d5a9717e9955aacd23df1d90c0e709&scene=21#wechat_redirect)  
  
  
[插上U盘自动装系统？Ubuntu无人化自动部署演示](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860400&idx=1&sn=5c014d32622634298be4a5ddc3e76885&scene=21#wechat_redirect)  
  
  
[从CentOS到Ubuntu：零成本迁移L2TP VPN，企业级内网穿透实战！](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860373&idx=1&sn=585ad234cc85b93a8c7352c1d13099f4&scene=21#wechat_redirect)  
  
  
[WireGuard太复杂？十分钟教你用Netmaker一键搞定全球组网](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860200&idx=1&sn=02207649d81cd9a38e595c792d616a81&scene=21#wechat_redirect)  
  
  
[云手机技术揭秘！低成本实现1台电脑变百部"虚拟手机"实战](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860286&idx=1&sn=a2051493387a022382f18716b2eeba5f&scene=21#wechat_redirect)  
  
  
[误以为是外国货？这家国产SD-WAN神器竟能免费白嫖，附Panabit免费版体验全记录](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859923&idx=1&sn=eed2d2c8d4482b7377a343222b9c063a&scene=21#wechat_redirect)  
  
  
[简单了解一下FortiFirewall、FortiGate和FortiOS的试用授权情况](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860452&idx=1&sn=b09450adc1db100f1434107b8517c8ab&scene=21#wechat_redirect)  
  
  
[iWAN隧道实测：一次握手跑满2.3Gbps，白嫖的SD-WAN真能吊打专线？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860028&idx=1&sn=e019aed0fb43e4971fc62c058da849b2&scene=21#wechat_redirect)  
  
  
[无需公网IPv4！手把手教你配置基于IPv6的WireGuard安全隧道](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859722&idx=1&sn=6a8c3d7f31fe3f4a8ef072c00656eb39&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5fL4uXAOMM7kUuIMJ8JGRicTGrVN3LAad2qWVLSLkZvOL0KSCibicfllib6L4g7Clp5vaZUhAgWoiahdV3kAHa2Wk6A/640?wx_fmt=jpeg "")  
  
  
