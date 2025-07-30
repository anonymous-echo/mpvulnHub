#  最新xxl-job综合漏洞检测利用工具|漏洞探测   
pureqh  渗透安全HackTwo   2025-06-04 16:01  
  
0x01 工具介绍  
  
  
xxl-job-attack  
 是一个用于检测和利用 XXL-JOB 系统漏洞的综合工具。该工具可以检测默认口令、未授权的Hessian反序列化漏洞、Executor未授权命令执行漏洞和默认accessToken身份绕过等问题。它支持通过内存马（如冰蝎Filter和Vagent）执行漏洞攻击，提供灵活的配置方式  
！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4EP8LM47ibjtGiamyib0cNYXE19pCNqTfLRuNsvkbduFnuBOqRr3dMnUYPMviaibPYCbejRkiazicGnqlcw/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具GUI界面  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4EP8LM47ibjtGiamyib0cNYXEbOCqubckwJJ1icYQ7JGWk0g4aUYiah94yurSL00k3O7PR6mI8lACfj3Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4EP8LM47ibjtGiamyib0cNYXEXdJRJCYKm4tOk4RT8v9psicxeeoqLzSaPmXQWgAgwPFmDnLceUynW6g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4EP8LM47ibjtGiamyib0cNYXE19pCNqTfLRuNsvkbduFnuBOqRr3dMnUYPMviaibPYCbejRkiazicGnqlcw/640?wx_fmt=png&from=appmsg "")  
# 该工具可检测以下漏洞：  
# 1、默认口令2、api接口未授权Hessian反序列化（只检测是否存在接口，是否存在漏洞需要打内存马验证）3、Executor未授权命令执行4、默认accessToken身份绕过  
# 关于内存马  
# 1、内存马使用了xslt，为了提高可用性提供了冰蝎Filter和Vagent两种内存马2、如需自定义可替换resources下的ser文件，其中filter.ser为冰蝎filter内存马、agent.ser为冰蝎agent内存马、xslt.ser会落地为/tmp/2.xslt,3、内容为使用exec执行/tmp/agent.jar、exp.ser则是加载/tmp/2.xslt4、vagent内存马连接配置:冰蝎:http://ip:port/xxl-job-admin/api, 其他类型内存马类似， 将api改为luckydayc、luckydayjs等即可5、Behinder内存马连接配置:密码: Sgjmccrzo请求路径: /api请求头: Referer: Lepxcnzd脚本类型: JSP  
  
6、由于agent发送文件较大，所以可能导致包发不过去，建议多试几次或者将超时时间延长  
  
7、由于Hessian反序列化基本上都是直接发二进制包，所以理论上讲其他的Hessian反序列化漏洞也可以打  
  
  
0x03 更新说明  
  
```
暂无
```  
  
  
  
0x04 使用介绍  
  
📦开箱即用，Java8一键启动  
```
 java8 -jar .\xxl-job-attack.jar
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4EP8LM47ibjtGiamyib0cNYXE19pCNqTfLRuNsvkbduFnuBOqRr3dMnUYPMviaibPYCbejRkiazicGnqlcw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
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
  
  
**公众号回复20250605获取下载**  
  
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
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
