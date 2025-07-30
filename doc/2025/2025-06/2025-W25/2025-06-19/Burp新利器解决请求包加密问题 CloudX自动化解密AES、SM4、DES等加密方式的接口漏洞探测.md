> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492539&idx=1&sn=250730046fc1116e0a28c8ea9e77bbb5

#  Burp新利器解决请求包加密问题 CloudX自动化解密AES、SM4、DES等加密方式的接口|漏洞探测  
cloud-jie  渗透安全HackTwo   2025-06-19 16:00  
  
0x01 工具介绍  
  
  
一直以来，我都在思考渗透测试过程中加密、防重放、签名的最优解决方案，市面上也出现了很多成熟的方案及工具，但始终无法在用户代码水平和更灵活之间找到平衡。有一段时间，我甚至认为无解，但最终，我还是找到了解决方案——这也是我认为的最终解决方案。  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！#渗透安全HackTwo**  
  
**下载地址在末尾**  
  
0x02   
功能简介  
  
  
插件Gui截图及功能特点  
  
**核心目标：**  
 为渗透测试过程中普遍存在的 **数据包加解密、签名校验、防重放**  
 等难题，提供一个**高度灵活**  
且**用户友好**  
的自动化解决方案。  
  
**核心功能与技术亮点：**  
  
**只需配置好规则即可实现加解密：**  
1. **基于规则的动态处理引擎：**  
  
1. 所有数据包处理行为（加解密、签名生成/验证、防重放处理、数据修改等）完全由用户定义的 **规则**  
 驱动。  
  
1. 规则是绝对的，理论上可以处理**任何符合逻辑**  
的数据包转换需求，提供了极强的灵活性。  
  
1. **透明的请求/响应处理流程：**  
  
1. **核心设计原则：**  
 进入 BurpSuite 的请求自动**解密**  
为明文；离开 BurpSuite 的请求自动**加密**  
为密文（用户操作过程无感知）。  
  
1. **效果：**  
 用户在 Burp 的 Repeater、Intruder、Scanner 等模块中操作的是**明文**  
数据包，工具自动在后台完成加解密转换，极大简化测试流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeI4c3O1knL9nYowud2WR62NrnzM8qMHq0WeUyJlGokJHrATPj4zibibyw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAe4ftzia1vmHuM8D8Mnuu74QgNA6tSJE6YBHJ7apC1sMBwEhY4bB4DSxA/640?wx_fmt=png&from=appmsg "")  
  
密文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeQLbfojogYGTgX4lwNBRJsIFTRdYmx4JicagExG1BTDbHibMbMia6FgqZg/640?wx_fmt=png&from=appmsg "")  
  
填写秘钥、iv即可实现加解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeLQDicCqCl4yJAtDshMoMtFCM0TTV2JgKFRqicTuxmkchtnBP4gCeMM7Q/640?wx_fmt=png&from=appmsg "")  
  
明文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeibwZfGB3Xia5rEtB5BI1V42Zia6qL90u0hk1OLic3vLFk9noQG8fcFjteA/640?wx_fmt=png&from=appmsg "")  
## 实战演示视频：  
  
##   
  
0x03 更新说明  
  

```
修复了可能导致的乱码bug
优化了代码逻辑，实现更稳，更快
```

  
  
0x04 使用介绍  
  
📦使用须知：  
  
- 不支持 orcale JDK or JRE 启动的 Burp  
  
- 采用 Montoya API 开发，不支持老版本 Burp，只会不断适配优化 Burp 最新版本的使用体验  
  
- 工具设计原则：所有进入 Burp 的数据包都是明文数据包，发出的数据包均为加密数据包（过程中用户无感知）  
  
- 理论上来说，本工具没有加密解密破签的说法，所有的一切均由规则驱动，所以配置规则才是用户需要做的事情  
  
- 请勿将明文数据包发往 CloudX，可能会导致某些功能异常  
  
- 如果规则执行不符合预期，可以在 logger 选项卡查看真实发出去的数据包  
  
  
  
使用技巧：  
  
- 你可能会注意到一个现象 —— 返回包是明文，但请求包看起来仍是密文。  
  
- 不用担心，其实规则已经生效了！这是因为 **Burp 的 Proxy → HTTP history 默认展示的是“原始请求”**  
，也就是未被工具解密前的数据视图。  
  
### 解决方案：  
  
  
方案一：手动切换为“已编辑请求视图” (点击展开查看截图)  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeWN1dIpdsScmCbRYqryPuSQiboc2suKJsBDVEUkRGk56HJFWQa3QRm2w/640?wx_fmt=png&from=appmsg "")  
  
方案二：设置默认展示“已编辑请求视图” (推荐) (点击展开查看截图)  
  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAek6OXcYpaIWWbFLjDicHO0MHr5PjUnR2icaAZSpn22pWpG59aTAuxsCJQ/640?wx_fmt=png&from=appmsg "")  
  
如何使用：  
## 步骤1（点击展开）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAejq4tONExannxKlYfHyjzZOJsXnt8xG8mteFUglOwRkQXkZIgXdXfmA/640?wx_fmt=png&from=appmsg "")  
##   
步骤2（点击展开）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5KIY5xLclrKG69xVTLyRAeejpN9p4icibpiafPTtdLicibKE956ic2zNJBhAiaxgB1JiaHlHpzpKqGjcgefw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1800多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250620获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
一款快速识别网站指纹3W+的Google插件|「指纹猎手」  
  
