#  JScanner一款隐藏Url接口探测/目录递归访问请求工具|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-05-08 00:00  
  
0x01 工具介绍   
          
在去年，我测试了无数网站，但是某些网站无论如何都不能搞定它，看了好多别人的实战思路，我总结出来了一点，那些大佬们总是会在前期在js文件当中收集信息，收集到别人在fofa还是鹰图上面探测不到了信息。于是我便想写一款工具来帮助自己在前期更好的探测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7IzGshduATGuEV2VFtnIQaYu8sWAPK8t4YwQMoR2g8qyPSknwq1lDEr4E87QhnJzZDjfPvyMN9VA/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介工具特点 提取网站的URL链接和解析JS文件中的URL链接探测网页源代码，发现js文件探测js文件，发现路径支持自定义状态码支持多URL请求支持目录的递减访问操作（更好的打出目录遍历漏洞）支持深度查找支持对标题与返回值长度的输出支持多URL的查找配合findsomething筛选出有效路径0x03更新介绍支持多URL的查找0x04 使用介绍python JScanner.py -h你可以看到具体的帮助文档默认情况下：python JScanner.py -u "https://example.com/xxxxx"设置请求间隔延时python Jscanner.py -u "https://example.com/xxxxx" -T 2设置header请求头python Jscanner.py -u "https://example.com/xxxxx" -r "{'cookie':'xxxx','user-Agent':'xxxx','xxxx':'xxxx'}"设置查找深度python Jscanner.py -u "https://example.com/xxxxx" -H 2建议：设置的查找深度不要超过2，或者有时候可以不进行设置设置最大递减python Jscanner.py -u "https://example.com/xxxxx" -l 1在默认情况下为0，表示全递减；举个栗子：假如你设置了1，则会将https://example.com/xxx/xxx/xxx，拆分为https://example.com/xxx/xxx，https://example.com/xxx/xxx/xxx；假如设置了0，则会全部进行拆分：https://example.com/xxx/xxx/xxx，https://example.com/xxx/xxx/，https://example.com/xxx/，https://example.com/设置您不想要的状态码python Jscanner.py -u "https://example.com/xxxxx" -B "(404,502)"输出为Excel表格的形式（推荐）python Jscanner.py -u "https://example.com/xxxxx" -o excel配合findsomething插件来完成信息收集将findsomething当中的路径复制到文本文件当中，使用下面的命令下面的命令不仅会使用当前的脚步内置的正则表达式来进行匹配，还会使用path.txt文件当中的路径进行拼接，最后去重输出。python Jscanner.py -u "https://example.com/xxxxx" -f path.txt  
0x05 内部星球VIP介绍-V1.3更新啦！  
       学习更多挖洞技巧可加入**内部星球**可获得内部工具和享受内部资源，包含网上一些付费漏洞扫描工具Fofa高级VIP。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复"   
**星球** "有优惠券名额有限先到先得！内部  
包含网上需付费未公开的  
**0day/1day****漏洞库**  
，后续资源会更丰富在加入还是低价！  
  
  
**👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240508获取下载地址******  
  
  
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
  
  
