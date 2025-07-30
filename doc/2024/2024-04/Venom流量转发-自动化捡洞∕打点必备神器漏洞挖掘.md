#  Venom流量转发-自动化捡洞/打点必备神器|漏洞挖掘   
漏洞挖掘  渗透安全HackTwo   2024-04-26 00:00  
  
0x01 工具介绍   
          
鉴于平时挖洞打点时用到被动扫描器，在挖洞时又喜欢在多台服务器上部署不同的代理扫描器，总会有捡洞的那一天，在使用Burp做流量转发的时候发现流量只能转发到置于首个的扫描器，于是又使用了passive-scan-client 该工具进行流量转发，但是还是不得我意，就花了一天上手搓了一个流量转发器出来，又花了一天调试和优化。针对使用过程中可能存在的问题已经做了处理，如：流量去重、无参静态文件过滤(这个还是针对黑名单个性化来的)、并发发包等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6Ia3wAviaH66KZKyRaDBuaOfc6Sd1ia1mtiba6gWANxkiaog28eO4fTeWkWpzJxL2DZNJjXjjTotWgsQ/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介工具特点联动被动扫描器：将流量转发至被动扫描器进行漏扫，不限制扫描器数量，只需在启动命令行处设置转发地址即可。联动爬虫工具：将爬虫工具的流量转发到Venom监听的端口上，由Venom给多个扫描器进行分发，工具：Rad、Crawlergo、Katana、URLFinder等。全支持，支持mac/windows/linux。0x03更新介绍针对使用过程中可能存在的问题已经做了处理，如：流量去重、无参静态文件过滤(这个还是针对黑名单个性化来的)、并发发包等。0x04 使用介绍参数说明Usage of Venom.exe:  -blackdomain string        黑名单域名，将那些风险/静态引用的域名（除共有域名外）不做转发至漏扫，以,分割 (default "aliyun.com,microsoftonline.cn,google.com,baidu.com,gstatic.com,shodan.io,taobao.com,jd.com,aliapp.org,mmstat.com,alicdn.com,alibaba.com,cnzz.com,youku.com,apple.com,twitter.com,amazon.com,github.com,bootstrapcdn.com,googleapis.com,fonts.net,jsdelivr.net,aliyun.com,bdstatic.com,youtube.com")  -blackfiletype string        黑名单文件名，只排除掉GET请求中无请求参数的黑名单文件，防止调用参数上存在其他漏洞，以,分割 (default "jpg,ttf,png,gif,jpeg,mp3,mp4,css")  -mustblackdomain string        绝对黑名单域名，就是只要域名中匹配到就不转发到扫描器中，这里针对那些公有域名，以,分割 (default "gov.cn")  -port string        Venom服务监听的端口，默认9090 (default "9090")  -proxy string        Venom服务代理地址(ip:port)，默认直连（为空），只支持socks5  -turnproxy string        被动代理地址集合，支持socks5/http协议，必须以http://xx:xx或socks5://xx:xx的形式，用,分割 (default "http://127.0.0.1:65530")  -workgroup int        启动线程数量，默认为10 (default 10)证书安装：正常配置好参数启动时，当前目录下会出现cert.key和cert.crt文件。然后按正常装Burp证书一样装到受信任的凭证里的根证书里就可以了，然后把浏览器代理设置到监听的端口即可（默认9090）操作示范：这里仅示范联动Burp、Xray、Yakit的使用教程（以顺丰为例）：Burp（65530端口）：Yakit（65531端口）：Xray（12345端口）：Venom联动展示：.\Venom -turnproxy "http://127.0.0.1:12345,http://127.0.0.1:65530,http://127.0.0.1:65531"关于为什么没配置其他参数，因为这里面黑名单里默认加了我喜欢屏蔽的一些接口，有其他的新增，请复制全之后加入即可，然后线程别开太大，容易吹风扇。关于效果上，上图已经全部包含。这里仅示范联动Crawlergo：  
0x05 内部星球VIP介绍-V1.3更新啦！  
       学习更多挖洞技巧可加入**内部星球**可获得内部工具和享受内部资源，包含网上一些付费漏洞扫描工具。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复"   
**星球** "有优惠券名额有限先到先得！内部  
包含网上需付费的**0day/1day**漏洞库，后续资源会更丰富在加入还是低价！  
  
  
**👉点击了解-->>内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240426获取下载地址******  
  
  
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
  
  
