> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492672&idx=1&sn=7e12184e991333cec5e692eaa1493756

#  About基于Python javalang库开发的一款轻量级Java源代码审计工具|漏洞探测  
Tr0e  渗透安全HackTwo   2025-06-26 16:01  
  
0x01 工具介绍  
  
  
**JavaSinkTracer**  
 是一款基于 Python javalang 库的轻量级 Java 源代码漏洞审计工具，通过“函数级”污点分析，从 Sink 点反向追溯调用链，规避变量级分析的断链问题。  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具特点  
  
此工具当前已实现的功能有：  
- 可在 Sink 配置文件中，自由拓展待检测的漏洞危险函数；  
  
- 自动构建 Java 源代码中所有函数的互相调用关系图call graph；  
  
- 从 Sink 点反向追溯到 Source 函数（可从配置文件的“depth”自定义追溯深度），提取调用链；  
  
- 程序自动识别“污点传播链路”上“不包含任何参数”的函数，排除不可能存在外部可控变量的链路；  
  
- 借助 Python javalang 三方库，自动提取每条“函数级污点链路”上所有函数的源代码，方便分析审计；  
  
- 自动生成漏洞报告（Md和html两种格式），Html报告支持漏洞栏目导航、漏洞代码高亮、代码变量跟踪等；  
  
## 效果  
## 以主流的开源 Java 漏洞靶场 java-sec-code 为例，扫描过程和漏洞报告效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5t8YuFBmLg5YcgBpdnwTomib4FmzryvD5b5DxEBkzRm20zzXIdn3zxmDD0c2AWwj8Q4chHV81HATQ/640?wx_fmt=png&from=appmsg "")  
##    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5t8YuFBmLg5YcgBpdnwTom58JkAUM4pQ2PKNtNVbKLBicCnJ1ba9K0Zltglu6yrQgUnnv4wzSb2SA/640?wx_fmt=png&from=appmsg "")  
## 漏洞的报告展示，以其中一个涉及到跨文件 SSRF 漏洞链路为例：   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5t8YuFBmLg5YcgBpdnwTomiaDmhxQkuFcq2DKm5XDhfpG8ZUbjrtZBwygjkM4YpFmSZbf0qKANDuQ/640?wx_fmt=png&from=appmsg "")  
##   
> 【注意】工具扫描出来的漏洞数量，受Sink点配置文件的影响。上述扫描过程我仅配置了简单的RCE、反序列化、SSRF漏洞Sink点的扫描结果，故并未覆盖此靶场的全量漏洞。  
  
  
****  
0x03更新说明  

```
Todo
以下功能留给读者自行拓展完善：
添加更多漏洞危险函数规则；
借助 AI 分析提取的污点链路代码；
精准化提取污点链路上的函数（当前并未考虑Java多态）；
此工具尚未经大量项目实践，可能存在诸多考虑不周导致的缺陷，欢迎反馈和共同改进。
```

  
0x04 使用介绍  
  
📦用法  
  
基础环境：  

```
pip install -r requirements.txt
```

  
运行命令：  

```
python JavaSinkTracer.py [-h] [-p PROJECTPATH] [-o OUTPUTPATH]
```

  
完整参数：  

```
λ python JavaSinkTracer.py -h
      ███████╗███████╗ ██████╗
     ██╔════╝██╔════╝██╔════╝
     ███████╗█████╗  ██║
     ╚════██║██╔══╝  ██║
     ███████║███████╗╚██████╗
     ╚══════╝╚══════╝ ╚═════╝
    Java源代码漏洞审计工具_Tr0e
usage: JavaSinkTracer.py [-h] [-p PROJECTPATH] [-o OUTPUTPATH]
JavaSinkTracer
options:
  -h, --help            show this help message and exit
  -p PROJECTPATH, --projectPath PROJECTPATH
                        待扫描的项目本地路径根目录，默认值：D:/Code/Github/java-sec-code
  -o OUTPUTPATH, --outputPath OUTPUTPATH
                        指定扫描报告输出的本地路径根目录，默认值：当前项目根路径下的 Result 子文件夹
```

  
  
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
最丰富！**（🤙截止目前已有1900+多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250627获取下载**  
  
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
  
  
