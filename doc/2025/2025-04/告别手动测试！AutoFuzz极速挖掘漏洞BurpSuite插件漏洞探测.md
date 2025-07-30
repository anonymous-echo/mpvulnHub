#  告别手动测试！AutoFuzz极速挖掘漏洞BurpSuite插件|漏洞探测   
z-bool  渗透安全HackTwo   2025-04-28 16:01  
  
0x01 工具介绍 AutoFuzz是一款针对BurpSuite的安全测试辅助插件，旨在提高测试效率。它通过自动识别请求中的参数，并根据预设的payload逐个进行发包测试，帮助安全研究人员快速发现潜在漏洞。该插件借鉴了经典的xia_sql项目，加入了参数解析优化与越权、未授权访问场景的集成，支持自动化渗透测试，特别适用于复杂的JSON参数测试。通过插件，用户可以轻松设置域名/IP、payload、Header等测试条件，进一步提升测试的精确度和效率。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！#渗透安全HackTwo  
**下载地址在末尾**  
  
0x02 功能简介  
### 主要功能  
#### 启用插件：顾名思义勾选后该插件启用。  
  
**监听 Proxy：自动捕获经过 BurpSuite Proxy 符合条件的请求。**  
  
**监听 Repeter：自动捕获 BurpSuite Repeter 中符合条件的请求。**  
  
**清空请求记录：清空右侧表格中的记录。**  
> **Tips：**  
> 通过监听捕获的流量相同接口只会 fuzz 一次。Method + Host + Path 均相同的请求视为同一请求。通过右键菜单发送到插件获取的请求，可无视域名/IP限制，无视去重限制。  
  
#### 域名设置  
#### 插件仅对用户设置的 域名/IP 相关请求发包测试，避免误伤无关站点。  
  
**添加域名/IP**  
  
点击左侧添加按钮即可添加域名/IP，每行一个，不可重复。  
  
![image-20250304001418561](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnKHhokM3TdQ4SicKSNibtw8JgiceS6OU1TeEXx4Ba9usscjfFdwtutn7Mw/640?wx_fmt=png&from=appmsg "")  
  
**编辑域名/IP**  
  
选中需要编辑的条目 ，点击左侧编辑，修改后确定。修改后数据不可重复，如果选中多条，则默认修改选中第一条。  
  
![image-20250304002312839](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPno3zX5kWjfrcFWYVdJ843oicTAYz9iayMVkakpX5gdYvv3rKCYguLUdwQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304002640059](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPn71oteJQ04BibSzTmF05xT0jibwjLkj3AEfYmqWkPw1HGiaBFzXhsJNzTQ/640?wx_fmt=png&from=appmsg "")  
  
**删除域名/IP**  
  
选中需要删除的条目，点击左侧删除，即可删除对应数据，支持多行选中删除。  
  
![image-20250304003218031](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnz7qvrUuVAjJWoj5IVld0lj4OSJJr93afibq49GHF0XGClrRDy0VFHdg/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304003238900](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnSjBP5JzYfOkeZ40DBQPVfPcmvTHUBIWa4Ciar6qL7eqEhzYsIB0cvbA/640?wx_fmt=png&from=appmsg "")  
  
**包含子域名**  
  
以 qq.com  
 为例，如不勾选包含子域名，则 host 为 y.qq.com  
 的请求无法被捕获。  
#### Payload 设置  
> Tips: 当 **列表中有数据**  
 时，才会启用该模块功能。  
  
  
**添加payload**  
  
点击左侧添加按钮即可添加 payload，每行一个，不可重复。  
  
![image-20250304211651127](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnUxXot3No5UXpxkwIqBrmvE6smq2tMVYEaOkFhopUaTGb4qFsZoKpmQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304211737496](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnQeC2ia4Uvwz6MdOYRQ9frNyfPoiaTjQ1RIg5X76oegvTIKP6XoM7muGQ/640?wx_fmt=png&from=appmsg "")  
  
**编辑payload**  
  
选中需要编辑的条目 ，点击左侧编辑，修改后确定。修改后数据不可重复，如果选中多条，则默认修改选中第一条。  
  
![image-20250304212242627](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPn7b9BOkYRriaYERx73PppzYPSIEjg4ceVfccrU2ePS5d9uibsKiaVx3pXQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304212334916](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnanKKsy7eed4d2LzvkXG7t7Wl7Et1Wib0M3j7iacOEqW4CGPabFHRDIvA/640?wx_fmt=png&from=appmsg "")  
  
**删除payload**  
  
选中需要删除的条目，点击左侧删除，即可删除对应数据，支持多行选中删除。  
  
![image-20250304214210463](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnxounyVLicemWuAiaHJTETUY8vOEnKj3OwjM3ZaCAJcYhFLrH0OfUu7Zg/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304214245111](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnyQicibMcY15Imy3KNx6yKB6cPWuDj8LG07x8qSbQTTuPT6juvBX221ag/640?wx_fmt=png&from=appmsg "")  
  
**参数置空**  
  
勾选后可增加一项为 空  
 的 payload，在 fuzz 时会将参数值置空。  
  
![image-20250304214330266](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnr3TryicWUg3bFpYMtyWHhsCXert1q8kW9ZbayGZe8wCzlIORWrN5wzg/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304215106091](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnOH06827OnnibBkGNe4lAyIrPzbMic5aPKXn47nMrFbmksUb9YbrMp2Gg/640?wx_fmt=png&from=appmsg "")  
  
**URL编码**  
  
勾选后，payload 中若存在特殊字符，非 json 格式的参数在 fuzz 时将对特殊字符进行 URL 编码。  
  
![image-20250304215342739](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnyQreejSCl48FRxKUERwb71gDMFHR4IzCfJXl7zwGBaibk7N1sibUdCUQ/640?wx_fmt=png&from=appmsg "")  
#### Auth Header 设置  
> Tips: 当 **列表中有Header数据**  
 或 **勾选未授权访问**  
 时，才会启用该模块功能。  
  
  
**添加Header**  
  
点击左侧添加按钮即可添加需要进行替换的 Header，每行一个，不可重复。  
  
![image-20250304222451866](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnBs1ibEqiaRb8wpccXBhoRuVKtcsVrTV9cVeleqxwwsdjnO8zL9IAW3dg/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304222531391](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnleWX5uGxk7ZicKoNV4bYQjRp1C5icVuZC46oRJH3sicEEuvpAWFMVTddg/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304222609482](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnKZCLtvmv14ZTm8UcicJxOrNBkwvdzmOkt7OI3e4fZnrzMSn2A1WaoKQ/640?wx_fmt=png&from=appmsg "")  
  
**编辑Header**  
  
选中需要编辑的条目 ，点击左侧编辑，修改后确定。修改后数据不可重复，如果选中多条，则默认修改选中第一条。  
  
![image-20250304222912568](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnRqJqKIalyyoRYnDTviaG7QaicpiaUPhr9Uugu4ZyXRl8yiacKxvFgTBT9A/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304222943732](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPn6toRdb9as0NPI7CxcQGJ7wsuEWhztSUVcgdqNO1ATAf8VKUvHpkiaVw/640?wx_fmt=png&from=appmsg "")  
  
**未授权访问**  
  
勾选后，在 fuzz 时会去除列表中设置的所有 Header，进行未授权访问测试。  
  
![image-20250304224510635](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnHibFLNicPnQrDiamOZboKX7gWNwNFSKYYyYSxJ4nauKVFK68wEhLjxGvg/640?wx_fmt=png&from=appmsg "")  
#### 查找功能  
#### 可根据设置的查找作用域在 request 或 response 中查找是否含有输入的字符串信息，不区分大小写，不支持中文查找。  
  
![image-20250304231940839](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnBgncR4a6Rlz6yPMol2JUSwBicwkbic9lR2WyM241jXR1tfDviav5IiauxQ/640?wx_fmt=png&from=appmsg "")  
#### 右键菜单  
#### 可通过右键菜单发送到插件，无视域名/IP范围，无视去重限制。  
  
![image-20250304235348677](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnHGiagvhTeSZGcJYzuWuELwiahiciaVMps0HEztCa0PTRc7s8w2tKkIa8cw/640?wx_fmt=png&from=appmsg "")  
  
![image-20250304235439669](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnhYj4eoMtexURI5iaD9gNf1ENuIibwVibPaHzk5ySYyZnJXThXgJyBg1GQ/640?wx_fmt=png&from=appmsg "")  
## 0x03更新说明增加域名黑白名单选项增加 payload 缓存增加表格返回包长度字段优化线程池处理逻辑0x04 使用介绍  
### 插件安装： Extender - Extensions - Add - Select File - Next  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnpfySic4AfBbGeiaypYM9aG47dRicdYnQUr4icjWmyH5wlgy0XoWLuPvtdQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4DovicI153cNtm947ibZQpPnZjSzIP0U0p5TcIt3cHaYSBpGGBhlmA0kVyGeibeJf8k8ic73Jazl5kPw/640?wx_fmt=png&from=appmsg "")  
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3800+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1700多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250429获取下载**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP星球福利介绍V1.4星球介绍(0day推送)**  
  
**2. 最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**3. 最新Nessus2025.02.10版下载**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard 10.2.128273破解版下载**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
