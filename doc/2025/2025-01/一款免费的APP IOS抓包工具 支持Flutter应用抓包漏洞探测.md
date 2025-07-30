#  一款免费的APP IOS抓包工具 支持Flutter应用抓包|漏洞探测   
wanghongenpin  菜鸟学信安   2025-01-26 00:30  
  
工具介绍   
**ProxyPin** 是一款免费开源的跨平台抓包工具，支持 Windows、Mac、Android、iOS 和 Linux。它可以拦截、检查并重写 HTTP(S) 流量，同时支持 Flutter 应用抓包。核心功能包括扫码连接设备、域名过滤、请求/响应修改（支持 JavaScript 脚本）、请求屏蔽、历史流量记录（支持 HAR 导出/导入），以及正则搜索和常用工具箱。基于 Flutter 开发，界面美观易用，非常适合调试与流量分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5x564Q3fHJgIHJaUibzaKFticlttO35KL3EicMbe5efIiap42XV0rKndglEQ/640?wx_fmt=png&from=appmsg&wxfrom=5&tp=wxpic&wx_lazy=1&wx_co=1 "")  
  
功能简介核心特性手机扫码连接: 不用手动配置Wifi代理，包括配置同步。所有终端都可以互相扫码连接转发流量。域名过滤: 只拦截您所需要的流量，不拦截其他流量，避免干扰其他应用。搜索：根据关键词响应类型多种条件搜索请求脚本: 支持编写JavaScript脚本来处理请求或响应。请求重写: 支持重定向，支持替换请求或响应报文，也可以根据增则修改请求或或响应。请求屏蔽: 支持根据URL屏蔽请求，不让请求发送到服务器。历史记录：自动保存抓包的流量数据，方便回溯查看。支持HAR格式导出与导入。其他：收藏、工具箱、常用编码工具、以及二维码、正则等Mac首次打开会提示不受信任开发者，需要到系统偏好设置-安全性与隐私-允许任何来源开源抓包工具 支持iOS/安卓/Windows/Mac/Linux全平台系统应该是目前支持最全的工具，全平台支持，您可以使用它来拦截、检查和重写HTTP（S）流量，ProxyPin基于Flutter开发，UI美观易用。更新说明V1.1.6新增Hosts设置, 支持域名映射工具箱新增时间戳转换编辑请求发送快捷键和发送loading修复脚本编辑键盘弹出安全模式问题修复脚本URL编码问题修复请求屏蔽编辑多出空格问题修复ipad分享点击无效问题修复高级重放次数过多不执行问题修复请求重写bug应用黑白名单增加清除无效应用，添加过滤已存在应用使用介绍选择对应的版本进行安装即可使用以下操作以Windows为例，打开工具后会默认进行HTTP抓包操作，看到的界面如下图所示默认情况下我们只能抓取HTTP请求，无法抓取HTTPS请求需要点击顶部的【启用HTTPS代理】开关按钮，安装根证书到本机根据软件进一步提示安装根证书  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5xWLbRjzsocpz7zXbFUn9Ml093OCLW7VEPJgiae6CbiaBNTFlnsjHibF8KA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
最后再启用HTTPS代理，就能抓取HTTPS请求了  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5xFaTkPZpKYztz3ia84MicKsb7XwOYlgYzEZWGIYJKX2I0iamj9aheHrJ9A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**项目地址**  
  
https://github.com/wanghongenpin/proxypin  
  
  
