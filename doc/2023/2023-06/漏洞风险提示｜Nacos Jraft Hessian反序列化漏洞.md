#  漏洞风险提示｜Nacos Jraft Hessian反序列化漏洞   
长亭安全应急响应  黑伞安全   2023-06-07 09:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicRa4AT1qj3nZePu4QWDNkpX9JibekoFZe4dmnuv9h2pvYc0HACBV06aIeDVMUGQUicluE3JictAoGN5g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "漏洞风险头图.png")  
  
Nacos是一个开源的、易于使用的动态服务发现、配置和服务管理平台，适合构建云原生应用。它提供了一种统一的数据管理和服务发现解决方案。近期，长亭科技监测到Nacos发布新版本修复了一个远程代码执行漏洞。经过漏洞分析后，发现该系统应用较为广泛，且漏洞影响范围较大。应急团队根据该漏洞的原理，编写了X-POC远程检测工具和牧云本地检测工具，并已向公众开放下载使用。长亭应急响应实验室发现，Nacos 1.x在单机模式下默认不开放7848端口，故该情况通常不受此漏洞影响。然而，2.x版本无论单机或集群模式均默认开放7848端口。主要受影响的是7848端口的Jraft服务，因此，用户可据此判断自身可能的风险。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
Nacos在处理某些基于Jraft的请求时，采用Hessian进行反序列化，但并未设置限制，导致应用存在远程代码执行（RCE）漏洞。  
  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
# X-POC远程检测工具  
检测方法：xpoc -r 100 -t http://xpoc.org工具获取方式：  
https://github.com/chaitin/xpoc  
https://stack.chaitin.com/tool/detail?id=1036  
#   
# 牧云本地检测工具  
检测方法：在本地主机上执行以下命令即可无害化扫描：./nacos_raft_deserialization_rce_scanner_linux_amd64 scan --output result.json  
工具获取方式：  
https://stack.chaitin.com/tool/detail?id=1175  
  
**影响范围**  
  
   
Affects   
  
  
  
**0****4**  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****5**  
临时缓解方案对外限制开放7848端口，一般使用时该端口为Nacos集群间Raft协议的通信端口，不承载客户端请求，因此老版本可以通过禁止该端口来自Nacos集群外的请求达到止血目的（如部署时已进行限制或未暴露，则风险可控）。升级修复方案官方已发布新版本修复了该漏洞，可下载参考链接中的最新版本进行升级。  
  
**产品支持**  
  
   
Support   
  
  
  
**0****6**  
洞鉴：支持以自定义PoC的方式检测该漏洞，已发布自定义PoC。云图：支持该漏洞的PoC特征检测，同时支持 2.x 版本的原理检测。全悉：已发布升级包，支持该漏洞利用行为的检测。牧云：漏洞情报升级包（VULN-23.06.003）已经在升级平台上发布。  
  
**时间线**  
  
   
Timeline   
  
  
  
**0****7**  
5月25日 长亭收到漏洞情报5月26日 漏洞影响初步研判6月2日 漏洞影响二次研判6月2日 漏洞研究与复现6月6日 长亭发布漏洞通告  
参考资料：  
  
✦   
https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
✦ https://github.com/alibaba/nacos/releases/tag/1.4.6  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否收到此次漏洞影响  
  
请联系长亭应急团队  
  
7*24销售，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
应急响应热线：4000-327-707  
  
  
  
