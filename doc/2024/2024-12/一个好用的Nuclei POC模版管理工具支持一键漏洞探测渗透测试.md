#  一个好用的Nuclei POC模版管理工具支持一键漏洞探测|渗透测试   
漏洞挖掘  渗透安全HackTwo   2024-12-09 16:00  
  
0x01 工具介绍   
          
Wavely是一个nuclei POC管理工具，支持模板的增删查改、请求响应包查看、并行扫描等功能，兼容MacOS、Windows和Linux系统。它采用全新的nuclei v3检测引擎，支持自定义DNSLOG服务器和多种模板导入方式，并提供主题切换、HTTP代理设置等功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq71X4MKJk4VM97TWVv4oTnKXnLBhPfCs2gicwdYVibMSC3X3LRNhuejCtiav2hNLWE1b5FM0ZDfmYj3Q/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介✨ 功能 实现nuclei poc管理的桌面应用，对nuclei模版的增删查改操作 支持查看nuclei模版请求响应包 支持MacOS、Windows和Linux操作系统 使用全新nuclei v3检测引擎 兼容yamlv2和yamlv3 nuclei template 实现多任务、并行扫描 支持自定义nuclei DNSLOG服务器 支持http代理（http、https、socks5） 支持主题切换 支持多种nuclei模版导入方式功能展示模版管理扫描任务选择thinkphp的poc进行扫描扫描结果扫描结果可复制扫描结果编辑nuclie模版编辑模版匹配请求包（需扫描匹配POC成功时才可看到请求响应包）匹配响应包（需扫描匹配POC成功时才可看到请求响应包）添加Nuclei模版App设置切换POC编辑器主题添加HTTP代理POC扫描参数设置模版导入功能0x03更新说明修复一些bug，比如目标输入错误的问题。0x04 使用介绍POC模版导入POC模版保存路径1. macos对于MacOS和Linux，首次打开App会在家目录生成模版文件夹ls /Users/$USER/.wavely/templates # macosls /home/$USER/.wavely/templates    # linux2. windows会在wavely.exe的同级目录下创建.wavely/templates，将POC放入此文件夹中（请开启显示隐藏文件/文件夹）。POC导入1. 在App中导入POC（带POC去重）点击从文件夹中导入按钮，选择nuclei poc文件目录。  
0x05 内部星球VIP介绍-V1.3（内部福利）        如果你想学习更多渗透挖洞技术/免杀/应急溯源技巧等等欢迎加入我们内部星球可获得内部渗透工具字典和享受内部资源，每周一至五周更新1day/0day漏洞，包含网上一些付费工具BurpSuite漏洞检测插件，木马webshell免杀等，Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！内部包含了网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍-1day/0day漏洞情报/资源每日更新  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20241210获取下载地址**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.3版本-星球介绍**  
  
**2. 最新Nessus2024.10.7版本主机漏洞扫描下载**  
  
**3. 最新BurpSuite2024.7.3专业版中英文版下载**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
