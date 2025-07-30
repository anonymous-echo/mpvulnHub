#  Mitmproxy GUI用于解决渗透测试加解密的难题 让你的Burp像测试明文这么简单|漏洞探测  
blackguest007  渗透安全HackTwo   2025-06-12 16:00  
  
0x01 工具介绍  
  
  
一个基于 Mitmproxy 的图形化代理工具，支持多种加密算法的请求拦截和修改。本项目提供了一个直观的图形界面，使得使用 mitmproxy 进行请求拦截和加解密变得更加简单。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6J3c2XyicHTOP6slV7Hczzg2icZzYDvzqEGMXfp6JzpMmdwd0Bd6ibTWicEyia4H3xJAIu9zBcdU4tXrw/640?wx_fmt=png&from=appmsg "")  
  
  
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
- 🖥️ 图形化界面，操作简单直观  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6J3c2XyicHTOP6slV7HczzggFiajT8QhLkUIxLFJKdqIDDB2YTL12O3UZC8VffwricUXdbDYWhHqKEQ/640?wx_fmt=png&from=appmsg "")  
  
- 🔐 支持多种加密算法：  
  
- RSA 非对称加密  
  
- DES (ECB/CBC) 对称加密  
  
- AES (ECB/CBC/GCM) 对称加密  
  
- Base64 编码/解码  
  
- 🔄 支持三种工作模式：  
  
- 加密模式  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6J3c2XyicHTOP6slV7HczzgwuXfPaYlw9LGuHJ7pgPfYDM4WVZkqOpjFyiaKXqFKowZMwNkxAyBZsA/640?wx_fmt=png&from=appmsg "")  
  
- 解密模式  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6J3c2XyicHTOP6slV7HczzgiaYTAVrcodaCY3ZibU4OOIrsW6BIrAoMNyzYV2wzqnFUumordibj5ewsg/640?wx_fmt=png&from=appmsg "")  
  
- 双向模式（同时支持加密和解密）  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6J3c2XyicHTOP6slV7HczzgkOhraMTz1pSjHiawJ6rAYTKibVkAZDZcA3wvu3p2LHe3FJoNbicEDKfng/640?wx_fmt=png&from=appmsg "")  
  
- 📝 支持多种数据格式：  
  
- JSON 数据  
  
- 表单数据 (x-www-form-urlencoded)  
  
- 📊 实时显示请求详情和日志  
  
- 🔢 支持多字段同时加解密  
  
- 🔌 支持自定义上游代理  
  
- 📁 自动保存加解密日志  
  
###   
  
0x03更新说明  
  
```
主要改进
1. RSA 密钥处理优化
修复了 Both 模式下密钥保存路径的问题
优化了密钥保存逻辑，确保密钥正确保存在 
bothTools
 目录
改进了密钥类型判断逻辑，更准确地识别公钥和私钥
2. 并发处理优化
改进了多线程处理机制，提高并发性能
优化了线程资源管理，减少内存占用
增强了线程安全性，避免资源竞争
改进了线程同步机制，提高稳定性
3. 代码结构优化
重构了项目目录结构，提高代码组织性
优化了模块划分，提高代码复用性
改进了类的设计，增强可扩展性
统一了代码风格，提高可读性
完善了异常处理机制
4. 日志系统增强
实现了异步日志记录机制
优化了日志格式，提高可读性
增加了日志分级（INFO、WARNING、ERROR）
改进了日志文件管理，支持自动轮转
增加了关键操作的日志记录
优化了日志性能，减少 I/O 开销
5. 界面优化
更新了版本号显示为 v1.0.1
优化了日志显示格式
改进了错误提示信息的可读性
6. 功能增强
完善了 Both 模式下的加解密流程
优化了密钥文件的保存和管理机制
增强了错误处理和日志记录
修复的问题
修复了 Both 模式下密钥保存到错误目录的问题
修复了密钥类型判断不准确的问题
修复了部分日志显示格式问题
修复了并发处理中的资源竞争问题
修复了日志记录可能导致的性能问题
修改both模式下rsa私钥加载问题
```  
  
  
0x04 使用介绍  
  
📦  
系统要求  
```
Python 3.8+
Windows/macOS/Linux
```  
## 安装步骤  
```
cd mitmproxy-gui
```  
```
```  
```
# Windows
python -m venv venv
.\venv\Scripts\activate
# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```  
```
```  
```
pip install -r requirements.txt
```  
```
```  
## 启动程序：  
```
cd src
python main.py
```  
```
```  
1. 选择工作模式（加密/解密/双向）  
  
1. 选择加密算法  
  
1. 设置监听端口（默认 8888）  
  
1. 设置上游代理端口（默认 8080）  
  
1. 输入需要处理的字段名（多个字段用逗号分隔）  
  
1. 输入密钥和 IV（如果需要）  
  
## 详细使用说明  
```
#工作模式
加密模式
监听指定端口
对请求数据进行加密处理
支持的数据格式：
application/json
application/x-www-form-urlencoded
#解密模式
监听指定端口
对请求数据进行解密处理
自动转发到上游代理
#双向模式
同时启动加密和解密代理
支持请求数据的实时加解密
自动处理上下游代理转发
#支持的加密算法
RSA
支持公钥加密/私钥解密
支持 .pem 格式密钥文件
支持 Base64 格式密钥
DES
支持 ECB/CBC 模式
支持自定义 IV（CBC 模式）
支持 PKCS7 填充
AES
支持 ECB/CBC/GCM 模式
支持自定义 IV（CBC/GCM 模式）
支持 PKCS7 填充
GCM 模式支持认证标签
Base64
支持标准 Base64 编码/解码
支持 URL 安全的 Base64 编码/解码
```  
## 项目结构  
```
mitmproxy-gui/
├── src/                    # 源代码目录
│   ├── main.py            # 主程序入口
│   ├── ui/                # 用户界面相关代码
│   ├── core/              # 核心功能实现
│   ├── controllers/       # 控制器
│   └── utils/             # 工具函数
├── scripts/               # 脚本目录
│   └── decryptTools/      # 解密工具
│       ├── aes_gcm.py     # AES-GCM 实现
│       ├── aes_cbc.py     # AES-CBC 实现
│       ├── aes_ecb.py     # AES-ECB 实现
│       ├── des_cbc.py     # DES-CBC 实现
│       ├── des_ecb.py     # DES-ECB 实现
│       ├── rsa.py         # RSA 实现
│       └── base64.py      # Base64 实现
├── logs/                  # 日志目录
├── resource/              # 资源文件
└── requirements.txt       # 项目依赖
```  
## 常见问题  
  
```
证书问题
首次使用需要安装 mitmproxy 证书
在浏览器中访问 mitm.it 下载并安装证书
端口占用
确保设置的端口未被其他程序占用
可以修改默认端口（8888/8080）
加解密失败
检查密钥和 IV 是否正确
确认数据格式是否符合要求
查看日志文件了解详细错误信息
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
  
  
**公众号回复20250613获取下载**  
  
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
  
  
