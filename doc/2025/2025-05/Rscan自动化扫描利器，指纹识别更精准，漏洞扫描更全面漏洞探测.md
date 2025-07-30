#  Rscan自动化扫描利器，指纹识别更精准，漏洞扫描更全面|漏洞探测   
CRlife  渗透安全HackTwo   2025-05-08 16:00  
  
0x01 工具介绍内网常见的工具fscan想必再也熟悉不过，但是发现一些企业内网中用市面一些工具已经很难达到预期效果，要么是出洞率太低，要么是效率太低，拿fscan为例，内置漏洞插件已经长时间没更新，指纹识别成功率太低，导致错过很多已有漏洞，面对企业大量内网资产进行梳理时，也鞭长莫及，所以观察到github大佬写的一个项目非常不错，具备可视化输出和资产梳理的功能，值得借鉴，但是这个工具比较综合，并不是一款偏向渗透化的工具，所以就参照大佬项目编写了一个漏扫工具。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！  
**下载地址在末尾 #渗透安全HackTwo**  
  
0x02 功能简介  
## 内置600种指纹识别，规则2000+  
## 支持hash、body、header等全面指纹识别  
OA系统泛微、通达、致远、用友、万户、蓝凌、金和、红帆、海昌、帆软、启莱、正方、信达、飞企互联、广联达、信呼等网络设备H3C、华为、思科、D-Link、深信服、TP-Link、锐捷等安全设备奇安信、绿盟、启明、安恒、齐治、宝塔、网康、山石网科等Apache组件Spark、Druid、Hadoop、kylin、Dubbo、APISIX、Solr、OFBiz、CloudStack、Airflow等监控设备海康、大华、宇视、中科智远、Cacti等  
和其他各种CMS系统ERP系统中间件等，由于数量太多，这里不列举，指纹准确率达到95%以上  
## 内置500+漏扫插件  
## 集成最新1day\nday漏扫插件，支持复杂http请求和反连，根据指纹命中漏扫插件，目前支持插件扫描数量如下  
  
海康26个、泛微58个、致远26个、亿赛通39个、金和21个、金蝶11个、宏景20个、广联达14个、飞企互联9个、大华26个、用友7个、万户14个、通达30个、深信服8个，同时支持shiro反序列化、各种组件中间件、Citrix、Confluence、VMware等共计**500+**漏扫插件  
  
还有很多指纹漏洞插件没有加入，后续持续加入  
## 支持弱口令检测  
## 支持SSH、MSSQL、MYSQL，RDP、FTP、 PostgreSQL、SMB、Telnet、 Tomcat、MangoDB、VNC、Oracle各种协议的弱口令检测  
## 端口扫描  
## 内置TOP100端口、TOP500端口、TOP1000端口  
## 0x03更新说明新增畅捷通、华天动力OA、蓝凌OA等POC插件30个，更新优化部分POC插件的准确性新增特色功能：新增POC详情报告的功能，每次扫描完毕后，在当前文件夹生成WEB漏洞详情报告，格式为html，可以查看数据包请求详情。0x04 使用介绍工具首次运行需要配置ceyeApi 和 ceyeDomain，目前仅支持ceye反连平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5o2X5MRvXt1k05Pr3wxsxPJn8ZQlPE7YNhZlGibhWdWr2JWluR93ODyTt6slGMDXSRp9tPibSsbzgA/640?wx_fmt=png&from=appmsg "")  
  
常见用法，ip.txt可以放域名或者ip，按行读取，支持对单个IP、域名、URL进行扫描  
```
scan -h                             #查看帮助
scan --ipfile ip.txt --noping       #读取ip.txt 禁ping扫描
scan -u http://www.example.com      #对单个url扫描
scan -i 192.168.1.0/24 -p top100               #对ip段扫描,使用top100端口
scan -i 192.168.1.1 -x http://127.0.0.1:8080   #对单个ip扫描,设置http代理
dirscan -u http://www.example.com   #对单个url目录扫描
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5o2X5MRvXt1k05Pr3wxsxPiakoTJ6mucOQBnSp2RWiazibaiccSCWjTrutF6VNFaFXeSB7ECxhjicjicpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5o2X5MRvXt1k05Pr3wxsxPdhJ0TOy4obz0dC6gWe8wLSicPQ9RPnBtBpJrhkkdqgtGbiax6LaLdYmQ/640?wx_fmt=png&from=appmsg "")  
##   
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多最新渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3800+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1700多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250509获取下载**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP星球福利介绍V1.4星球介绍(0day推送)**  
  
**2. 最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**3. 最新Nessus2025.02.10版下载**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard 10.2.128273破解版下载**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
一款快速识别网站指纹3W+的Google插件|「指纹猎手」  
  
