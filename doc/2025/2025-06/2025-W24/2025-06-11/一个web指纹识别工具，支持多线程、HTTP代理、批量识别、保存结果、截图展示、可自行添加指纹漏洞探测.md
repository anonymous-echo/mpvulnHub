#  一个web指纹识别工具，支持多线程、HTTP代理、批量识别、保存结果、截图展示、可自行添加指纹|漏洞探测  
login546  渗透安全HackTwo   2025-06-11 16:01  
  
0x01 工具介绍  
  
  
httpgo 是一款高效的开源 Web 指纹识别工具，专为网络安全设计，支持多线程、HTTP 代理和批量 URL 识别。它能快速识别网站技术栈，生成 CSV、JSON、HTML 格式结果，并提供截图展示。用户可自定义指纹规则，灵活匹配网页内容、标题、图标哈希等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENiba1TibPqq1dNLkG6Ht4ictqyhibuSVicLCqqTpcQWWBicFGqSibAko4kSmhGxQ/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具GUI界面介绍  
### 单个url识别  
###   
### 批量url识别  
```
-file 指定批量url文件，每行一个url
-output 指定输出文件夹名称，不用加后缀，会在指定的文件夹生成csv,json,html文件
-thead 指定并发数，未设置默认20
```  
  
![image-20240828135258064](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibaujNFVctNIPar5tibtx7H5SuF9yRLmwicUeBd772FEnkJuKxFc5IicSzibg/640?wx_fmt=png&from=appmsg "")  
  
会在指定的-output的路径下生成对应的result.csv表格文件![image-20240828135511437](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibastK7HtqKkpNZxrglwjWNyjx5teSCc99PkYBPdBUGSWA5PmAzgRjGGA/640?wx_fmt=png&from=appmsg "")  
  
  
同时也会生成result.html网页文件和指纹信息result.json文件  
  
如果想查看result.html页面，可以使用-server 开启web服务，自动生成一个加密的web服务  
  
![image-20240828135747673](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibaVR8vHKRvONzZfRFgaDAayzhU2j1SuSIp4PEicywnteKic3I47XvxWN4Q/640?wx_fmt=png&from=appmsg "")  
  
![image-20240828135942331](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibayno5dgZLaLibgtkbuiaTZDaCnD8dR9ezYGiaYicliaUdIMDsAfsqkBPFQAQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20240828140106825](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibarJJydicoGH3ahF3YTqyBicFJbXGbvwGVHa3Av5HicxwxkzS5hrGhAIxiaQ/640?wx_fmt=png&from=appmsg "")  
  
当输入账号密码认证过后，可直接访问根目录，下载csv文件，方便在服务器部署时，下载csv结果![image-20240828140231253](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibaMjDcZA9oGhmyFAcOFBKy9Ba9QWmHcUAkolBOPxzPSCjahSthib3YbsA/640?wx_fmt=png&from=appmsg "")  
  
  
或在html结果路径下使用python3 -m http.server 3333起一个web服务![image-20240815120249467](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibahxWgK7Xwvvo0GK2kqGiaMJLLd17Bw0ueFMzr5VmKDVbw1szym8hkkgg/640?wx_fmt=png&from=appmsg "")  
  
  
访问target.html![image-20240815120309736](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibauThqCJjKtt9A1zmOI0kD0FWLj5EEZzSg4hwCSHEM2281jHoOGuX0OQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击对应的蓝色按钮可仅查看对应指纹信息如点击【苏迪WebPlus Pro--个性化门户集群平台】![image-20240815120332257](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5Y3J9ozGX8FD5Wib4U8ENibaK4uqc9yeiaqVnH7xAByQFoyrhGfxpCIvhDwB6QrNIADxz0vxNiceGAiaA/640?wx_fmt=png&from=appmsg "")  
  
###   
  
0x03更新说明  
```
add fingers
```  
  
  
0x04 使用介绍  
  
📦命令帮助  
```
[shym]% go run main.go -h
 _       _     _
| |__   | |_  | |_   _ __     __ _    ___
| '_ \  | __| | __| | '_ \   / _' |  / _ \
| | | | | |_  | |_  | |_) | | (_| | | (_) |
|_| |_|  \__|  \__| | .__/   \__, |  \___/
                    |_|      |___/
Usage of :
  -check
    	检查新添加指纹规则的合规性
  -file string
    	请求的文件
  -fingers string
    	指纹文件 (default "fingers.json")
  -hash string
    	计算hash
  -output string
    	输出结果文件夹名称,不用加后缀(包含csv,json,html文件) (default "output")
  -proxy string
    	添加代理
  -server string
    	指定需要远程访问的output的文件夹名称，启动web服务，自带随机密码，增加安全性
  -thead int
    	并发数 (default 20)
  -timeout duration
    	超时时间 (default 8ns)
  -url string
    	请求的url
```  
## 指纹规则  
```
title="xxxxx" 匹配title的内容
header="Server: bbbb"	匹配响应标头Server的内容
icon_hash="1111111"	匹配favico.ico图标hash内容
body="cccc"	匹配body中的内容
cert="dddd"	匹配证书中内容
body="xxxx" && header!="ccc" 匹配body中包含xxxx并且header中不包含ccc的内容
=为包含关系，即包含关系即可匹配
!=为不包含关系，即不包含关系即可匹配
支持逻辑 && 以及 || 和 ()比如
body=\"aaaa\" && (title=\"123\" || title=\"456\")
双引号"记得转义，如果是搜索的具体内容里有"需要在"前加\\\",如
body=\"<link href=\\\"/jcms/\" 匹配的为body中是否包含<link href="/jcms/
{
  "name": "jcms or fcms",
  "keyword": "body=\"<link href=\\\"/jcms/\" || body=\"<link href=\\\"/fcms/\" || body=\"jcms/Login.do\" || body=\"fcms/Login.do\""
}
如果是搜索的具体内容里有&或|需要在他们前面使用\\,如
body=\"1234\\&\\&1111\" 匹配的为body中是否包含1234&&1111
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
最丰富！**（🤙截止目前已有1800+多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250612获取下载**  
  
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
  
  
