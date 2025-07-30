#  Burpsuite被动探测与递归目录探测插件|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-04-18 00:02  
  
0x01 工具介绍   
        JsRouteScan是使用java语言根据burpsuite api编写的burpsuite插件。  
插件通过被动扫描的方式，根据指定正则列表在响应包中匹配疑似路由的字符串，然后可以根据设定，被动探测根目录或者其他目录。也提供了将匹配到的路由作为payload，递归探测当前网站所有路径中的每一层路径。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Mibp6pRK0nMYyoIZQ3Tb8YdYEQ2icyhiaJIwd4bCibcwDkT64keD1mlzulalHRCuOVPM8BMqjcbjEEA/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介工具特点装载插件：Extender - Extensions - Add - Select File - Next初次装载插件会在用户目录/.config/JsRouteScan/目录下生成config.yaml文件，其中包含了Regexs（在响应中匹配路由的正则表达式列表）ExRouteRegexs（在响应中排除路由的正则表达式列表）ExSuffix（排除匹配相应的后缀列表，符合列表中后缀的请求将不会在响应中匹配路由）Config面板用来设置插件中被动探测的一些配置，此面板中的配置会应用到所有匹配的网站中。0x03更新介绍2024-04-10 加入自定义head头功能，设置后对当前网站生效2024-04-10 优化线程池，动态调整线程数2024-04-10 递归加入确认请求数量2024-04-10 获取到路由的url打印0x04 使用介绍使用说明PassiveStart按钮：被动探测启动按钮，开启后所有匹配到的路由都会以Passive Scan Path中的值作为根目录来请求。CarryHead按钮：携带请求头按钮，开启后所有由插件发起的请求均会携带原始请求头。（此请求头为第一次获取到路由的请求头）Thread Pools Number：线程池的线程数Request Method：请求的方式，包含GET与POSTPassive Scan Path：被动探测的根目录，默认为/ReqDisplay面板用来存储获取到路由的网站host头，与当前网站获取的路由，以及当前网站的扫描结果。右边的配置只会对当前网站起效。Scan Root Path：主动扫描的根目录Scan按钮：点击后会获取PATH中的所有路由，对当前网站发起扫描，根目录为Scan Root Path的值Recursion-Scan按钮：递归扫描，点击后会获取PATH中的所有路由，然后递归对当前网站的每一层路径进行扫描SetHead按钮：点击后会设置当前网站的head头，生效需打开Config的CarryHead按钮scan面板用来展示请求的内容以及扫描的内容，此面板不会自动更新，需要右键Refresh  
0x05 内部星球VIP介绍-V1.3更新啦！  
       学习更多挖洞技巧可加入**内部星球**可获得内部工具和享受内部资源，包含网上一些付费工具。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复"   
**星球** "有优惠券名额有限先到先得！内部  
包含网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！  
  
  
**👉点击了解-->>内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240418获取下载地址******  
  
  
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
  
  
