#  一款越权漏洞检测的 Burp 插件 内置AI模块辅助分析大幅降低误报率效|漏洞探测   
漏洞挖掘  渗透安全HackTwo   2024-11-19 16:01  
  
0x01 工具介绍   
AutorizePro🧿 是一款基于 Autorize 开发的 Burp Suite 插件，专注于越权漏洞检测。通过新增 AI 分析模块和优化逻辑，大幅降低误报率（从 99% 降至 5%）。用户可通过配置低权限验证头和拦截规则，实现自动化检测并辅助人工分析。支持阿里云通义千问 API，提供高效越权检测及结果比对，显著节省时间和精力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq78Xbjiass72gJ5wibvv70MXdW5JmicadY79uutXfMKCVZN4BB58tV165OAShlbjBcNwn15OjtM3d36A/640?wx_fmt=png&from=appmsg "")  
  
**下载地址在末尾**  
  
0x02 功能简介工具背景- 越权漏洞在黑盒测试、SRC挖掘中几乎是必测的一项，但手工逐个测试越权漏洞往往会耗费大量时间，而自动化工具又存在大量误报, 基于此产生了AutorizePro。  
  
### 工具亮点  
- 优化检测逻辑 && 增加 AI 分析模块(可选项) ，将原始工具误报率从 99% 降低至 5% ，从海量误报中解脱出来  
  
- 对于需要人工确认的告警可通过展示页面并排查看 原始请求、越权请求 以及 未授权请求 的数据包方便对比差异。  
  
###   
### 🌠 使用效果示例  
> 🌟 大幅降低误报: 从下图中可以看出，启用AI分析后，你只需要去分析一个请求是否真正越权，人工投入的分析精力节约95%以上。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq78Xbjiass72gJ5wibvv70MXdNdiaPa1PmDpj3BwsZ4KYG4G3fHz5dNuEFCicoTmEnDdGLgdNK3Q74WQg/640?wx_fmt=png&from=appmsg "")  
> 查看AI判定越权的具体请求，可同时展示越权请求、原始请求、未授权请求，方便对比差异  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq78Xbjiass72gJ5wibvv70MXdWl29ceHDDQDaNXqCDamKgxbR5icxLGSCJ2kkhGVv6eMxDymNkKRVFfA/640?wx_fmt=png&from=appmsg "")  
0x03 更新介绍更新内容根据历史用户反馈优化了未授权的检测 && 越权检测逻辑配置界面的上下分割符可任意调整位置，便于配置展示配置界面的按钮统一增加到下方文本框部分增加纵向 && 横向 滚动条，方便查看修改Table Filter (状态过滤栏) 增加对AI分析结果列的过滤配置选项0x04 使用介绍1️⃣安装 AutorizePro 插件1. 下载代码仓库zip包到本地，解压2. 打开 Burp Suite，导航到 Extender -> Extensions -> Add3. 在 Extension Type 选择框中，选择python4. 在 Extension file 选择框中，选择代码仓库中 AutorizePro.py 文件路径AutorizePro 插件安装完成界面 🎉💡 可通过 拉动 中间的侧边栏调整展示页和配置页的显示比例2️⃣ 使用 AutorizePro 插件1. 打开配置选项卡：点击 AutorizePro -> Configuration。2. 通过fetch cookie header按钮获取最新请求的验证头 或 手动复制低权限用户的验证头（通常是 Cookie 或 Authorization），并将其复制到标有 “Insert injected header here” 的文本框中。注意：如果请求中已经包含了该头部，插件会替换现有的头部，否则会添加新头部。3. 如果不需要进行未授权的测试（即不带任何 cookie 的请求，用于检查接口是否存在身份验证，而不仅仅是低权限用户的越权检测），可以取消勾选 Check unauthenticated (默认开启)。4. 勾选 Intercept requests from Repeater，通过 Repeater 发送的请求也会被进行插件处理。5. 点击 AutorizePro is off 按钮启用插件，让 AutorizePro 开始拦截流量，并进行授权检测。6. 打开浏览器，并配置代理设置，使流量能够通过 Burp 代理。7. 使用高权限用户访问你想测试的应用程序，测试修改类资源时可使用 Match/Replace 配置越权测试时需要修改的资源信息。8. 在 AutorizePro 插件的左侧结果展示界面中，你将看到请求的 URL 和 对应的权限检查状态。9. 目前仅支持阿里云通义千问 api key(sk开头); 如何获取API-KEY: https://help.aliyun.com/zh/model-studio/developer-reference/get-api-key)。10. 当启用 API-Key 时，符合AI分析触发条件的请求会交由 AI 进一步分析，结果将展示在 AI. Analyzer 列。11. 点击左侧展示页面的某个 URL，可以查看它的原始请求、修改后的请求以及未经身份验证的请求/响应，方便你分辨差异。❓检测状态说明Bypassed! (红色) : 判定越权Enforced! (绿色) : 判定不存在越权Is enforced??? (please configure enforcement detector): 无法判断，可以在enforcement detector 进一步配置越权特征协助判断🌟 Tips:    Is enforced??? 状态表示插件无法确定接口是否做了权限控制，可通过 enforcement detector 进一步配置权限校验特征来辅助判断。    eg:    如果某个接口对于越权访问请求会返回 "无权限" 这个指纹特征，    你就可以将这个指纹特征添加到 Enforcement Detector 过滤器中，这样插件判断时就会查找这个指纹特征，区分出实际已鉴权的接口，减少误报。🚰 过滤器配置：在 Interception Filters 配置拦截规则拦截过滤器位可以配置插件需要拦截哪些域名 或 拦截带有什么特征的请求。你可以通过黑名单、白名单、正则表达式或 Burp 的范围内的项目来确定拦截的范围，以避免不必要的域名被 AutorizePro 拦截，减少对不关注的请求的拦截分析。⚠️安全提示：因为工具涉及cookie替换重放，强烈建议 配置Interception Filters 指定拦截的站点，以免cookie泄漏至其他站点 🌟 默认配置会避免拦截脚本和图片，你也可以新增更多静态资源类型的忽略规则。💰 AI分析功能需要花多少钱？(默认根据工具检测逻辑判断，AI需要用户启用之后才会生效)。。为最大程度减少AI分析带来的经费消耗,启用AI分析之后仅自动检测 状态码相等 && 响应为json格式 && 长度小于3000 的数据包;若不符合条件，AI分析功能将不会生效。⚠️注意：当启用AI分析功能时，您应该尽量在 Interception Filters 中配置拦截的 域名 / 规则 以免检测非目标站点带来的经费消耗。AI分析功能需要先开通模型调用服务，在 阿里云百炼首页顶部提示。https://bailian.console.aliyun.com/#/home进行开通：阿里云通义千问API计费说明，新开通的都有免费额度 https://help.aliyun.com/zh/model-studio/billing-for-model-studio( 个人测试消耗示例：在插件开发调试期间全天较高频率测试且没有限制域名，全天消耗总费用0.38元，实际上线采用的模型成本减半，速度更快)  
0x05 内部星球VIP介绍-V1.3（福利）        如果你想学习更多渗透挖洞技术/技巧欢迎加入我们内部星球可获得内部工具字典和享受内部资源，每周一至五周更新1day/0day漏洞，包含网上一些付费工具BurpSuite漏洞检测插件，Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！内部包含了网上需付费的0day/1day漏洞库，后续资源会更丰富在加入还是低价！👉点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍-1day/0day漏洞情报每日更新  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20241120获取下载地址**  
  
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
  
  
