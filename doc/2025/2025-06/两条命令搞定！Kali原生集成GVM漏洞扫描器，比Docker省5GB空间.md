#  两条命令搞定！Kali原生集成GVM漏洞扫描器，比Docker省5GB空间   
原创 衡水铁头哥  铁军哥   2025-06-05 23:45  
  
我们前面介绍了如何在Ubuntu系统中部署GVM/OpenVAS  
（[6年旧镜像翻车！手把手教你用Docker部署最新版企业级漏洞扫描工具OpenVAS](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860633&idx=1&sn=5b6cc0f21b97d658225bc4e366ee3398&scene=21#wechat_redirect)  
  
），也简单创建了几个扫描任务测试了一下功能  
（[Windows消失、路由器变种？Greenbone社区版多模式扫描实战，这些坑别再踩](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860654&idx=1&sn=66263e79839a3587eeb55fbc6bff8012&scene=21#wechat_redirect)  
  
）。  
  
有小伙伴感觉在Docker中部署略显复杂，尤其是拉取镜像比较费劲，那还有什么简单快捷的方法吗？  
  
还真有，在Kali系统中，仅需几条命令即可快速完成部署，我们来一块学习一下。  
  
首先，你得有一台Kali Linux主机  
（[如何将Kali系统部署到U盘？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458859186&idx=1&sn=ce9c48429f4b42fb172b17d569a28a34&scene=21#wechat_redirect)  
  
），并且完成软件包列表更新和系统升级，因为Greenbone社区版需要使用最新版本的PostgreSQL。  
```
apt update && apt upgrade -y
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRKmUSUwSWDB1H3lp2ibibiaFyWGicRKz55ibutQFvgGP1qiaEvwoneWpVvbgQ/640?wx_fmt=png "")  
  
接下来的安装可以说是非常简单了，仅需执行一条命令即可安装Greenbone社区版和所需的依赖项：  
```
apt install gvm -y
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aREhjUY1WheJgpubCZIQWia7tshPeD4ibtXVLDm1vQeyd2mePVIibrLOE7A/640?wx_fmt=png "")  
  
可以看到，仅仅下载了不到4 MB的文件，并且磁盘空间占用也只有16.7 MB。  
  
然后，我们就可以运行自动配置脚本来完成安装。  
```
gvm-setup
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aR4xQH9EeqEeCzWCCC2hmElL8xMYk6ZKlnnglJ1Zb2cT7yQTPpNLBvHA/640?wx_fmt=png "")  
  
gvm-setup的设置过程很快，在回显信息中，我们需要记录为管理员用户admin创建的默认密码，如图中框选的部分。  
  
接下来，我们可以使用Kali自带的用于验证已安装服务的脚本来检查GVM设置状态，运行脚本的命令如下：  
```
gvm-check-setup
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRZqdh3swGroT2AKy6WsX21XcBHVQxta01zoPZ9b2oUJmuAVVXJ4lj4A/640?wx_fmt=png "")  
  
可以看到，经过一共9项检测，最终提示GVM-25.04.0安装成功。同时，我们还能看到各组件的版本信息，例如OpenVAS扫描器的版本是23.20.1，Notus扫描器的版本是22.6.5，ospd-OpenVAS的版本是22.9.0，gvmd（GVM Manager）的版本是26.0.0，组件版本比Docker版本要新一些。不过，NVT数量只有93947个，只有Docker版本的58 %。  
  
不过Kali中的GVM默认使用的是HTTPS，能提供更好的数据安全性。我们通过浏览器访问GSA页面https://127.0.0.1:9392，提供前面自动生成的管理员密码进行登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRibgsUHMhtGOu2xVbQg0g1pd1bkicGnxjCUc6Lgv8zJvYcCkCRrz1IwIQ/640?wx_fmt=png "")  
  
在开始第一次扫描之前，Greenbone需要解析漏洞提要并将其存储到PostgreSQL数据库中。我们可以通过左侧导航栏“Administration”下的“Feed Status”页面，检查NVT提要状态。跟Docker部署一样，这一步也需要耗费很长的时间，在初始化结束之前执行扫描任务，无法保证任务正常执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRkibLbiaf6AMFQI4eibN8uo9VBPC1e6rpZY1jiaKPia0IvGST3PBgDnEiaVWQ/640?wx_fmt=png "")  
  
图中的NVT数据包含在漏洞扫描期间创建结果的文件，OpenVAS扫描器处理.nasl文件，Notus 扫描器处理.notus文件。SCAP数据包含CPE和CVE信息。CERT数据包含来自德国DFN-CERT和CERT-Bund机构的漏洞信息。GVMD数据（也称为“数据对象”）包括扫描配置、合规性策略、端口列表和报告格式。从版本信息来看，更新时间就是当天的。  
  
同步过程由两部分组成：1、通过rsync下载更改，2、通过守护进程将更改加载到内存和数据库中。我们可以使用greenbone-feed-sync命令来触发同步。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aR3odicwthNXnOeFUHY2ASk9N2MHiawBZyZyBnHo83liahZ0tIqSREicpHjQ/640?wx_fmt=png "")  
  
等待所有漏洞提要同步完成之后，好像数量上也差不多。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRKBGd6b16CBDQZPwrhGl7DHuDfNppWKUjCB2G1cic8Lib03MXdORC3xCQ/640?wx_fmt=png "")  
  
默认情况下，Greenbone社区版仅允许本地主机通过IP地址127.0.0.1访问GSA WEB页面。如果我们想启用WEB页面的远程访问，可以通过修改gsad的systemd服务文件/usr/lib/systemd/system/gsad.service来实现，例如将--listen参数的值更改为0.0.0.0以监听所有网卡，并可选择将--port参数的值更改成标准的HTTPS端口443：  
```
nano /usr/lib/systemd/system/gsad.service
ExecStart=/usr/local/sbin/gsad --foreground --listen=0.0.0.0 --port=443
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aR8icHicq8ibQeicRPq1nQIYUPiaWCDsOibYLS9qvMnao4ic53FQhz4Tiad0tvbQ/640?wx_fmt=png "")  
  
之后，重新加载并重新启动gsad服务就可以了。  
```
systemctl daemon-reload
systemctl restart gsad
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5fL4uXAOMM7dZQUZkeN8C8z19TAmc4aRXN80Anibt5h1jHvMGXoEZUIJd8DHtcXDQ2tvXdFlEKgXbT0wUcyggjQ/640?wx_fmt=png "")  
  
从磁盘空间来看，Kali版本大约占用了17 GB，跟Docker版本相比，又瘦身了不少。  
  
  
**推荐阅读***  
  
[在Windows强跑Docker，8GB内存都喂不饱漏洞扫描神器？](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860603&idx=1&sn=3f138383a35ce7cfbe9c538da4af941e&scene=21#wechat_redirect)  
  
  
[Windows消失、路由器变种？Greenbone社区版多模式扫描实战，这些坑别再踩](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860654&idx=1&sn=66263e79839a3587eeb55fbc6bff8012&scene=21#wechat_redirect)  
  
  
[6年旧镜像翻车！手把手教你用Docker部署最新版企业级漏洞扫描工具OpenVAS](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860633&idx=1&sn=5b6cc0f21b97d658225bc4e366ee3398&scene=21#wechat_redirect)  
  
  
[告别ADB！用DHCP选项让手机自动添加静态路由](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860514&idx=1&sn=c127b47f41e0d02b9dab6806ad72c4ad&scene=21#wechat_redirect)  
  
  
[Windows也能玩转Docker！手把手教你部署Redroid云手机](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860580&idx=1&sn=c038284c0081dbfa540f2196c2be6f76&scene=21#wechat_redirect)  
  
  
[高性能游戏云手机革命！GPU加速让Redroid性能追平小米15](https://mp.weixin.qq.com/s?__biz=MzI4NjAzMTk3MA==&mid=2458860530&idx=1&sn=4f8d8d70812910fcbd0b06ab0c67c6d7&scene=21#wechat_redirect)  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5fL4uXAOMM7kUuIMJ8JGRicTGrVN3LAad2qWVLSLkZvOL0KSCibicfllib6L4g7Clp5vaZUhAgWoiahdV3kAHa2Wk6A/640?wx_fmt=jpeg "")  
  
  
