#  6年旧镜像翻车！手把手教你用Docker部署最新版企业级漏洞扫描工具OpenVAS   
原创 衡水铁头哥  铁军哥   2025-06-03 23:43  
  
我们前面尝试通过Windows版的Docker部署OpenVAS  
（[在Windows强跑Docker，8GB内存都喂不饱漏洞扫描神器？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860603&idx=1&sn=3f138383a35ce7cfbe9c538da4af941e&scene=21#wechat_redirect)  
  
），结果失败了。总结一下原因，首先是镜像问题，我选择了下载量最高的mikesplain/openvas镜像，但是这个镜像已经6年了，自带的证书已经过期，导致无法访问管理页面；其次是系统问题，Windows中的Docker桌面版由于虚拟化的问题，额外占用了很多系统资源，导致镜像加载异常缓慢，影响使用体验。  
  
其实，除了搜索OpenVAS的Docker镜像之外，我们还可以参考官方指导，使用社区版Docker镜像，官方指导手册链接如下：  
```
https://greenbone.github.io/docs/latest/index.html
```  
  
官方指导中给出了三种部署方式，原理都是一样的，就是根据docker-compose.yml文件进行部署，区别就是操作的自由度不一样。  
  
第一种是复制Greenbone官方给出的docker-compose.yml文件内容，可以参考配置文件中的提示进行自定义调整，自由度最高，但部署过程也最复杂；第二种就是直接下载docker-compose.yml文件，然后手工启动；第三种是快速部署方案，可以在新安装的系统上，直接使用一键部署的脚本，完成Docker组件安装、部署OpenVAS到启动管理界面的全部流程。  
  
一键部署的命令如下：  
```
curl -f -O https://greenbone.github.io/docs/latest/_static/setup-and-start-greenbone-community-edition.sh && chmod u+x setup-and-start-greenbone-community-edition.sh && ./setup-and-start-greenbone-community-edition.sh
```  
  
为了方便大家了解整体过程，我们采用第二种部署方式来演示一下。  
  
首先，最新版的Greenbone社区版支持Debian bookworm、Ubuntu 24.04 LTS、Fedora 35/36和CentOS 9 Stream系统，我们本次使用Ubuntu 24.04的服务器版系统。最低系统配置为2核CPU、4 GB运行内存和20 GB存储空间，推荐使用4核CPU、8 GB运行内存和60 GB磁盘以上的系统配置。  
  
确认系统安装必须软件包ca-certificates、curl和gnupg。  
```
apt install -y ca-certificates curl gnupg
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecWhkQBL4BrL3TZEiaNeOIwXfcwTTxQB1yxhkgkqLvF3kbaJK8hmHFeGg/640?wx_fmt=png "")  
  
可以参考我们之前的介绍完成Docker引擎的部署  
（[Ubuntu 22.04.4安装Docker引擎](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458855710&idx=1&sn=05ffcb6bce4b2aedb03e1e7f65de128a&scene=21#wechat_redirect)  
  
）。  
```
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoeceHXW2eCq777X0cLunVlBeBMcMSicqt7z0FQvmvO8F1DicajmjM6hDIRQ/640?wx_fmt=png "")  
  
准备工作完成之后，我们可以直接下载官方最新的docker-compose文件。  
```
curl -f -O -L https://greenbone.github.io/docs/latest/_static/docker-compose.yml
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecfGsQvsfxdJrctvN1vIvXVQVfCUukZaTfryIBhLCRDjxuhibZuYupG5A/640?wx_fmt=png "")  
  
有了这个现成的docker compose文件，我们就可以拉取Greenbone社区版的容器镜像了。虽然是海外，但是通过IPv6网络可以直接访问  
（[告别NAT！腾讯云服务器IPv6实测：多1跳却快2ms，配置+防火墙规则一篇搞定](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859664&idx=1&sn=f166b67b643651a55b878c35437344c5&scene=21#wechat_redirect)  
  
）；镜像比较大，拉取可能耗费一定时间。  
```
docker compose -f docker-compose.yml pull
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecPEWXx1dibias3j5T2U7k5NQAKQ0ZFwYzea72Kq1FtjOrsfGGKesbcianw/640?wx_fmt=png "")  
  
查看Docker镜像信息，发现最早的也只有4个月，最新的是几小时之前的，相比之前用的版本，确实新了很多。镜像大小方面，合计大概5.2 GB，加上Docker引擎占用的部分，操作到这一步，磁盘就已经消耗6 GB了；如果启动OpenVAS容器，大概又会占用22 GB磁盘空间。这样看来，最低配要求的20 GB存储空间在没有包含软件部分的情况下都说少了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecH0SSbeLo0OxeE5vf1zfJEkpjCzzrzJp1ZnN1UOEPdogbGxnt8yf0jw/640?wx_fmt=png "")  
  
接下来，我们就可以启动Greenbone社区版OpenVAS容器了。  
```
docker compose -f docker-compose.yml up -d
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoeclkeKKYdtjOlBSHNficY7kjG8yuTNXYmXxnII1wgrxObHLFKOpH1QymQ/640?wx_fmt=png "")  
  
需要注意的是，运行容器时需要加载提要数据，此过程可能需要几分钟到几小时，我本次耗时大约一小时。在数据未完全加载之前，扫描将显示不充分或错误的结果。要获取所有服务的连续日志输出流，可以运行以下命令来显示日志消息：  
```
docker compose -f docker-compose.yml logs -f
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecfk4v9nLEyyUNuZGn9RS94nhR7sSuu5WA0bJpheJGBKB2M53nCLywZQ/640?wx_fmt=png "")  
  
输出信息非常多，如果不想查看，可以按Ctrl+C停止日志流。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecDoX8r75icFNFo5m1cQSUDIjWnc81llXxfXQ8p3FgYHkibTgMicysrAbLg/640?wx_fmt=png "")  
  
等待服务完全启动并加载所有提要数据后之后，我们就可以通过9392端口访问OpenVAS的管理页面GSA（Greenbone Security Assistant）了。  
  
默认登录页面为http://192.168.0.173:9392/，默认用户名和密码均为admin，建议使用以下命令更新自定义的管理员密码：  
```
docker compose -f docker-compose.ym \
    exec -u gvmd gvmd gvmd --user=admin --new-password='<password>'
```  
  
请注意，如果密码包含特殊字符（如$），则需要用单引号括起来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecqE53dxMAN3BgXtz5f2cibbZjqoCXKeHWrdtmxGMXAxYa5nDoHhHsMcA/640?wx_fmt=png "")  
  
登录之后的看板页面如下所示，可以看到统计的29万+   
CVE（  
  
C  
  
ommon   
  
V  
  
ulnerabilities and   
  
E  
  
xposures，通用漏洞与暴露），还有16万+的  
NVT（  
  
N  
  
etwork   
  
V  
  
ulnerability   
  
T  
  
est，网络漏洞测试）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoec5iaKUd8icibYUROycFklt4xH30LGHpNqlK36Tv94poGJvib3gQjHT7U0hw/640?wx_fmt=png "")  
  
切换到导航栏Scans下的Tasks模块，可以执行扫描任务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoeccPjiccibTVE2BxtZDR6xQ85pM4xaW8icWibBFRQANh0jtD5eIO8YyLItRQ/640?wx_fmt=png "")  
  
点击页面上的魔术棒图标，选择【Task Wizard】即可快速开始扫描任务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecclGE6eVZrtDbovFWD4tJyXAgh9sqocBmkh8mv42o8mG0Fk8BiaVswIg/640?wx_fmt=png "")  
  
默认情况下，IP地址这里会带出当前访问的主机IP地址或者网关地址，只需要修改IP地址即可快速创建扫描任务。我们把这个IP地址换成宿主机IP地址扫描试一下。  
  
任务执行过程中，计算资源占用倒不是很高。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecx8icCZUWZFbPCcoFYGoDoRljxzbYZNYQGsBJyQKLtrBoSzTlXngMPhw/640?wx_fmt=png "")  
  
等待扫描结束我们就可以查看扫描报告了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecQlZlVem3fzqrl5AWuyNxyP60bb7KvxpETicXaoLyOrfuWaq4PWutvDA/640?wx_fmt=png "")  
  
任务执行结束之后，可以通过以下命令停止OpenVAS容器。  
```
docker compose -f docker-compose.yml down
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM4LTeIFzKtLAbRRwg7VDoecUzfVUfIIYvo4oX0A63tVKPuMn8l30lglaZHdJiaxdtwGdc23CKNnicyA/640?wx_fmt=png "")  
  
这么一来，一个简单的扫描任务就结束了，你学废了吗？  
  
  
**推荐阅读***  
  
[在Windows强跑Docker，8GB内存都喂不饱漏洞扫描神器？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860603&idx=1&sn=3f138383a35ce7cfbe9c538da4af941e&scene=21#wechat_redirect)  
  
  
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
  
  
[iWAN隧道实测：一次握手跑满2.3Gbps，白嫖的SD-WAN真能吊打专线？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860028&idx=1&sn=e019aed0fb43e4971fc62c058da849b2&scene=21#wechat_redirect)  
  
  
[无需公网IPv4！手把手教你配置基于IPv6的WireGuard安全隧道](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859722&idx=1&sn=6a8c3d7f31fe3f4a8ef072c00656eb39&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5fL4uXAOMM7kUuIMJ8JGRicTGrVN3LAad2qWVLSLkZvOL0KSCibicfllib6L4g7Clp5vaZUhAgWoiahdV3kAHa2Wk6A/640?wx_fmt=jpeg "")  
  
  
