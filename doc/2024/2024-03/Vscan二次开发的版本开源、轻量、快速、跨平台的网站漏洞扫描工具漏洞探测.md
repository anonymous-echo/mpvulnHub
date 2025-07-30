#  Vscan二次开发的版本开源、轻量、快速、跨平台的网站漏洞扫描工具|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-03-11 00:00  
  
0x01 工具介绍   
  
          
基于veo师傅的漏扫工具vscan二次开发的版本，开源、轻量、快速、跨平台 的网站漏洞扫描工具，帮助您快速检测网站安全隐患。功能 端口扫描(port scan) 指纹识别(fingerprint) 漏洞检测(nday check) 智能爆破 (admin brute) 敏感文件扫描(file fuzz)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5v9c84e9icULMhX4icK5cXcvZ7iaOVfk9r7UViaaWvRz0ic84QR0ZrMl990BLAPniaLicmAOq2fHEDbwYLw/640?wx_fmt=png&from=appmsg "")  
  
  
**下载地址在末尾**  
  
0x02 功能简介特点根据原vscan开发文档，用户可以自定义指纹和poc，两者的调用关系是：先检测指纹，再调用对应poc，类似于nuclei前不久更新的-ac命令行的检测功能，都是基于指纹来检测漏洞根据原vscan开发文档，指纹对应的xray poc命名格式为：指纹-xxxx-yml，因此对新增的poc进行了格式统一，包括： 泛微oa  用友oa 通达oa thinphp spring-boot springblade apache-tomcat drupal microsoft-exchange sangfornuclei则是通过tags加载poc0x03更新介绍ehole指纹更新nuclei检测脚本更新xray检测脚本更新支持xray yml v2语法修复nuclei模板读取缺失字段报错规范指纹名称，nuclei、xray检测脚本命名格式0x04 使用介绍常见用法VscanPlus -host http://127.0.0.1  
0x05 内部星球介绍-V1.3  
        加入  
内部星球可获得内部工具和享受内部资源。  
  
详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅后台回复"   
**星球**  
"有优惠券名额有限先到先得！后续会增加**ChatGPT4**供内部成员使用现在加入还是低价！  
  
  
**点击了解-->>内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4hKvWPTNgyoH9rAUre3WIWYx6tnCTsiaN05tUh2swhsd4xmMbiaAPAYE1Libk7Tu9KvWeLLnYc4HGdQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5v9c84e9icULMhX4icK5cXcvmRhfcoFWI83xRYbAGO52e66dNaO2ghtl80JJMm44bav4AQl7sxcVeA/640?wx_fmt=png&from=appmsg "")  
  
****  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240311获取下载地址******  
  
  
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
  
  
