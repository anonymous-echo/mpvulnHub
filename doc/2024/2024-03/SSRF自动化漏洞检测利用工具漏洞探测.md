#  SSRF自动化漏洞检测利用工具|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-03-29 00:01  
  
0x01 工具介绍   
          
SSRFmap 是一个用于自动化发现和利用服务器端请求伪造（SSRF）漏洞的工具。根据您提供的信息，这个工具可以将一个 Burp Suite 的请求文件作为输入，然后针对其中的特定参数执行模糊测试。SSRF 是一种漏洞，攻击者可以利用它迫使服务器代表他们执行请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7wVoib7gA5fL9kUkU9bXng47sQo2X7ly0OYgjKKed1xibIvGicKmnlZV0hGpaXafpBWrPB9iccSlk9Ug/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介以下模块已实现，可以与 -m 参数一起使用。 名字 描述fastcgi 快速CGI RCEredisRedis RCEgithubGithub Enterprise RCE < 2.8.7zabbixZabbix RCEmysql MySQL命令执行postgresPostgres 命令执行docker通过 API 的 Docker 信息泄漏smtp SMTP 发送邮件portscan扫描主机的前 8000 个端口networkscanHTTP Ping 扫描网络readfiles读取文件，例如 /etc/passwdalibaba从提供程序读取文件（例如：元数据、用户数据）aws从提供程序读取文件（例如：元数据、用户数据）gce从提供程序读取文件（例如：元数据、用户数据）digitalocean从提供程序读取文件（例如：元数据、用户数据）socksproxy SOCKS4 代理smbhash通过 UNC 路径强制进行 SMB 身份验证tomcat针对 Tomcat Manager 的暴力攻击custom将自定义数据发送到监听服务，例如：netcatmemcache将数据存储在 memcache 实例中SSRFmap工具的data目录下有一个example.py文件，用来检测框架是否能够正常运行，它这个文件就是用来搭建一个ssrf的漏洞环境使用抓包软件yakit抓取一个存在ssrf的漏洞数据包读文件python ssrfmap.py -r 1.txt -p url -m readfiles-r:指定数据包-p:指定漏洞参数-m:指定检测的模块扫描端口python ssrfmap.py -r 1.txt -p url -m portscan0x03更新介绍添加与服务交互的模块0x04 使用介绍安装cd SSRFmappip3 install -r requirements.txt使用介绍python3 ssrfmap.py  usage: ssrfmap.py [-h] [-r REQFILE] [-p PARAM] [-m MODULES] [-l HANDLER]                    [-v [VERBOSE]] [--lhost LHOST] [--lport LPORT]                    [--uagent USERAGENT] [--ssl [SSL]] [--level [LEVEL]]  optional arguments:    -h, --help          show this help message and exit    -r REQFILE          SSRF Request file    -p PARAM            SSRF Parameter to target    -m MODULES          SSRF Modules to enable    -l HANDLER          Start an handler for a reverse shell    -v [VERBOSE]        Enable verbosity    --lhost LHOST       LHOST reverse shell    --lport LPORT       LPORT reverse shell    --uagent USERAGENT  User Agent to use    --ssl [SSL]         Use HTTPS without verification    --proxy PROXY       Use HTTP(s) proxy (ex: http://localhost:8080)    --level [LEVEL]     Level of test to perform (1-5, default: 1)  
0x05 内部星球VIP介绍-V1.3更新啦！  
       加入**内部星球**可获得内部工具和享受内部资源，包含网上一些付费工具。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复"   
**星球** "有优惠券名额有限先到先得！内部  
包含网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！  
  
  
**👉点击了解-->>内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240328获取下载地址******  
  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
**2. 最新BurpSuite2023.12.1专业版中英文版下载**  
  
[3. 最新Nessus2023下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247484713&idx=1&sn=0fdab59445d9e0849843077365607b18&chksm=cf16a399f8612a8f6feb8362b1d946ea15ce4ff8a4a4cf0ce2c21f433185c622136b3c5725f3&scene=21#wechat_redirect)  
  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
