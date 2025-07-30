#  让Druid未授权访问漏洞危害最大化案例和利用工具|挖洞技巧   
漏洞挖掘投稿  渗透安全HackTwo   2025-02-16 16:02  
  
0x01 前言   
       Druid是阿里开发的数据库连接池，广泛用于监控和数据管理。常见的安全漏洞主要有两种：未授权访问和弱口令问题。若发现Druid未授权访问，利用druid_sessions工具快速获取 Alibaba Druid 的相关参数（sessions, sql, uri, jdbc ），然后就可以利用Burpsuite进行遍历sessions验证是否可用，如果运气好就可以利用session进入后台或者getshell 啦**（末尾下载工具)**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1F74H3r50rsynLEZ5OzH4D9r4sFfO88CgHoKPKC1HNNkzMqsmicK8TzPg/640?wx_fmt=png&from=appmsg "")  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
**末尾可领取挖洞资料文件**  
0x02 漏洞案例一  
通过目录扫描发现 Druid，通过访问 URI 监控发现文件上传接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FSI4SpzwdzzI9sJrz6OmS9SL1gxIn0895Sr2ic0HNfDU4L7Uf2rgWriaA/640?wx_fmt=png&from=appmsg "")  
  
发现存在 Session，利用工具druid_sessions把 Session 保存下来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FAiaKJ9Buz8l3Jmwjw6rQruI4agTs5AORfFQlzdPY7DQNbLGuqMiaalrQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FLZOKZ2ZnWaVAIxoVB7jgxT24063yF2md8If5uFEu51KdMnibic3fpooQ/640?wx_fmt=png&from=appmsg "")  
  
找个需要登录的链接爆破 Session，这是失效的 session  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FUnLHFpGjhKGkSJnGSZ8l9NrLqpQtIVD77ibSWkL8FqrIx3lNtrYyLTg/640?wx_fmt=png&from=appmsg "")  
  
这是可以利用的 session  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FDmqRd7787Yibc3fKVYWdA0EXkbQeQkJZ0rL0hbbzYyYJ5CtBxOSVcxw/640?wx_fmt=png&from=appmsg "")  
  
文件上传需要登录，所以需要上面的 session，尝试上传 jsp 提示非法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1F6wRdmAqtIgbEL5Nic1I5uyGBBbg8Q2ZNgjxYAn60ibuGCyTCDDxB7ibtw/640?wx_fmt=png&from=appmsg "")  
  
随意输入一些后缀名，发现可以成功上传，说明是任意文件上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1F6YYDVgk9IvDXiabHoMAwWD92CW38BSf0AYO8lMGTEMjb5NGoGEAQicJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7GS6VadfeeySwicAFeUdt1FvwHiazHAtIRTuvicibLXB1h0gFCrdCdbz75EYsbcickpcGVc5mNNUW0eoA/640?wx_fmt=png&from=appmsg "")  
  
  
0x03 漏洞案例二cwkiller师傅的利用文章当开发者配置不当时就可能造成未授权访问下面给出常见Druid未授权访问路/druid/websession.html/system/druid/websession.html/webpage/system/druid/websession.html(jeecg)当遇到需要登录的Druid是可能存在弱口下面给出Druid常见登录口路径。/druid/login.html/system/druid/login.html/webpage/system/druid/login.html以上路径可能不止存在于根目录，遇到过在二级目录下的，我们扫路径时可能就关注根目录这个点可以注意一下Druid的一些利用方式通过泄露的Session登录后台直接在/druid/websession.html页面ctrl+a复制整个页面内容到EmEditor删除红框部分，点击制表符这样就可以直接复制了，也可以通过其他方式处理，个人比较喜欢这个方式然后再到URI监控处找一条看起来像登录后台才能访问的路径（可用home等关键词快速定位）此处设置爆破，将刚才得到的Session值填入，因为此处的session值存在一些特殊符号需要关闭burp默认的url编码200即为有效session，用改cookie的插件改成有效的就能进入后台测试通过URI监控测试未授权越权由于有的Druid可能Session监控处没有东西，可以通过URI监控测试未授权越权0x04 总结        最后总结，Druid常见漏洞为未授权访问和弱口令问题，危害较低，但通过以上两个案例方法利用druid_sessions工具可快速提取Session、SQL等敏感数据，结合Burp爆破劫持后台权限，甚至通过文件上传或越权接口实现Getshell，直接升级为高危或严重漏洞。喜欢的师傅可以点赞转发支持一下谢谢！0x05 内部星球VIP介绍V1.4（福利）如果你想学习更多渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源。1.每周更新1day/0day漏洞刷分上分，目前已更新至3500+。2.包含网上一些付费工具/BurpSuite漏洞检测插件/fuzz字典等等。3.Fofa会员Ctfshow各种账号会员共享等等。4.最新SRC挖掘/红队/代审视频资源等等。5. .....6.详情直接点击下方链接进入了解，后台回复" 星球 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！点击下方地址全面了解👇🏻👉点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**20250217**  
" 获取工具下载地址  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**" 获取 一些字典已重新划分处理**（需要内部专属字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
  
回复“**书籍**" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.01.06版本主机漏洞工具**  
  
**3. 最新BurpSuite2024.11.2专业（稳定版）**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
