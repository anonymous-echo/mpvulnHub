#  【漏洞复现】可以白嫖别人的AI模型了？你的被白嫖了吗（Ollama）   
小C学安全  小C学安全   2025-03-01 00:06  
  
‍  
  
# 免责申明  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9G5ibPSK1E937W8cNeV9WEtSSeibTyEq3Yo7Hl1KCEficUEeNnAYbm6baw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9eBylTaLog8BjQZCCVUCZhG8HeXD1T131maF324xm3PS0JXESHwzoDw/640?wx_fmt=png&from=appmsg "")  
  
本公众号的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9cUnPQfWsyicM5GOVWGZIAWScIEHuyenVfDwicM49mOibuBibk1iar4rmBkA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9vJ7tgutQEV1EWDo10rSn0mQiaoWppRK21J8tBUf7NqUnxUeDVHU9q7Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
# 前言  
  
近期，Deepseek 大模型的本地部署热度持续攀升，众多技术爱好者和企业纷纷投身其中，尝试在本地部署大模型以搭建专属知识库。在这一过程中，由于在互联网上广泛流传的部署文章大多是依照默认配置进行指导，从而引发了一系列严重的安全隐患。大量部署在互联网上的 Ollama 大模型服务器暴露出未授权漏洞和远程命令执行漏洞等。  
  
基于此，本文将深入探讨如何复现这些漏洞，帮助安全人员和技术人员更深入地了解漏洞原理，以便更好地进行防范。在复现过程中，将详细展示利用漏洞的步骤、工具以及可能遇到的问题和解决方法。同时，针对存在问题的服务器，本文还将提供全面且专业的加固方案，包括但不限于身份验证机制的完善、访问控制策略的优化、输入验证和过滤规则的强化等。通过这些措施，确保服务器的安全性，有效防止他人未经授权使用大模型资源，切实保障大模型部署的安全性和稳定性，为用户和企业提供可靠的技术支持。‍  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9xnO5TsvVyicxM9fkX5yztCsibR47sGAR0DyxpJhlnAECiamEicFGHo46tA/640?wx_fmt=png&from=appmsg "")  
  
  
  
# Ollama 大模型存在以下风险点  
## API 接口相关风险  
  
**接口无授权访问风险**  
  
Ollama 在默认情况下未设置身份验证和访问控制功能，其服务 API 接口  
  
可在未授权情况下被调用。攻击者可远程访问接口，调用私域大模型计算资源，窃取知识库内容，还可能投喂虚假或有害信息，干扰模型正常运行和输出。  
  
  
  
**历史漏洞导致的潜在风险**  
  
如曾存在的 CVE-2024-39722 漏洞，是 api/push 端点中的路径遍历漏洞，曾暴露服务器上存在的文件以及部署 Ollama 的整个目录结构。虽在 0.1.46 版本修复，但如果未及时更新版本，仍可能存在风险。  
  
  
## 模型自身安全风险  
  
**拒绝服务（DoS）攻击风险**  
  
存在一些可导致 DoS 攻击的漏洞，如 CVE-2024-39720 是越界读取漏洞，可通过 /api/create 端点导致应用程序崩溃，从而引发 DoS 情况；CVE-2024-39721 在将文件 “/dev/random” 作为输入传递，重复调用 /api/create 端点时，会导致资源耗尽并最终导致 DoS。  
  
  
  
**模型中毒风险**  
  
可通过来自不受信任来源的 /api/pull 终端节点导致模型中毒，攻击者可能通过该方式向模型注入恶意数据或指令，影响模型的准确性和可靠性，使模型输出错误或有害的结果。  
  
  
  
**模型盗窃风险**  
  
存在可能导致通过 /api/push 终端节点向不受信任目标进行模型盗窃的漏洞，模型可能被未经授权的用户窃取，造成知识产权损失，或被用于恶意目的。  
  
  
## 其他风险  
  
**算力盗用与服务中断风险**  
  
大量 Ollama 大模型服务器 “裸奔” 在互联网上，攻击者可通过自动化脚本扫描到暴露的服务器，恶意占用大量计算资源，导致算力被盗取，部分用户服务器崩溃，造成服务中断，影响正常使用。  
  
  
  
**数据隐私风险**  
  
若使用不知名厂商提供的基于 Ollama 的大模型服务，一些不良厂商可能会使用被盗资源对外售卖，同时实时监控用户提交的所有数据，造成用户隐私泄露。  
  
  
# 互联网资产  
  
通过  
fafa  
查询互联网上的ollama资产  
```
app="Ollama"
```  
  
22,063 条匹配结果  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9se5XhMyF3tBz1B8UkwDX36wyrlpaCyU1ab49UUeyjmaVV4QjbB2EaQ/640?wx_fmt=png&from=appmsg "")  
  
# 漏洞复现  
  
本文主要复现未授权漏洞和远程命令执行漏洞（CVE-2024-37032），使用本地部署搭建的环境  
## 未授权漏洞  
  
一般默认部署，会开放默认端口11434，如访问提示“Ollama is running ”代表服务器上运行了Ollama 服务器。这也是未授权的标志  
有些测试脚本就是通过识别服务器是否返回“Ollama is running ”来验证是否存在漏洞  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9VicLPXwQccOZ96WOiazdchsCvTPjQsMsMnHUCZviacuJkJhRz00lDFXgg/640?wx_fmt=png&from=appmsg "")  
  
访问模型接口：/api/tags。可以看到部署了三个大模型：嵌入模型和两个deepseek-r1 1.5b和7b模型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO97kJpm6kTvUbHbKrrVicrE1icm2xYOeicFYlktIQGfSUicalAu7WLDv7giaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO95222WWp3skWo2zL1cpdunaIdvV2eU2BGoqCMmF37eiaGB85ibpZhKOPg/640?wx_fmt=png&from=appmsg "")  
  
如果你部署了chatboxai、cherry等AI管理工具，可以通过工具连接大模型。  
例如：  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9yAOK9tePnqNqkoCHCNkA28OlIlXwvKJSbiaDknSOxibTvdHQ97cGWZdw/640?wx_fmt=png&from=appmsg "")  
  
上图显示已经连接成功，可以直接使用了。  
还有一些高危API接口，如下：  
  
<table><thead><tr class="ue-table-interlace-color-single" style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n27" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">接口</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n28" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">请求方法</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n29" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">风险等级</span></span></span></span></th><th style="box-sizing: border-box;"><span cid="n30" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">操作内容</span></span></span></span></th></tr></thead><tbody><tr class="ue-table-interlace-color-double" style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n32" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">/api/pull</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n33" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">POST</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n34" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">严重</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n35" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">远程下载任意模型，若未授权或被恶意利用，可能导致服务器被植入恶意模型或占用大量资源</span></span></span></span></td></tr><tr class="ue-table-interlace-color-single" style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n37" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">/api/delete</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n38" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">DELETE</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n39" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">高危</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n40" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">删除已有模型，存在被未经授权的用户利用来删除关键模型，影响业务正常运行的风险</span></span></span></span></td></tr><tr class="ue-table-interlace-color-double" style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n42" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">/api/generate</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n43" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">POST</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n44" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">中危</span></span></span></span></td><td style="box-sizing: border-box;"><span cid="n45" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""><span textstyle="" style="color: rgb(0, 0, 0);">模型推理操作，在输入验证不严格时，可能被攻击者利用进行恶意推理请求，干扰正常服务</span></span></span></span></td></tr></tbody></table>  
  
## 远程命令执行漏洞（CVE-2024-37032）  
  
影响版本：Ollama < 0.1.34  
攻击者可通过路径穿越写入恶意文件，最终控制服务器。  
  
**漏洞利用思路：**  
  
在Ollama的server/modelpath.go代码中，digest参数未对用户输入进行有效过滤，攻击者通过/api/pull或/api/push接口提交包含路径穿越符（如../../）的请求，将恶意文件写入系统关键路径（如/etc/ld.so.preload），触发动态库劫持，实现远程代码执行  
  
（RCE）。  
  
  
  
**漏洞验证截图：**  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAun1zoytHmhvedKtgPfKwO9QnBleH0AfNatV7e3fZJvDTVq8TJujhYO5TMGbiarMT2vhM8dVAgT1rA/640?wx_fmt=png&from=appmsg "")  
  
# 整改加固建议：1.若Ollama只对本地提供服务，建议设置环境变量Environment=“OLLAMA_HOST=127.0.0.1”，仅允许本地访问。2.若Ollama对外提供服务，建议1）修改config.yaml、settings.json配置文件限定可调用Ollama服务的IP地址；2）在防火墙等设备部署IP白名单，严格限定访问IP地址；3）通过反向代理实现身份验证和授权，防止未经授权用户访问。  
# 下载链接  
  
远程命令执行漏洞（CVE-2024-37032）测试工具  
  
公众号回复“20250228”  
  
  
# 关注公众号  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAv32gdTbe7FeVicMw5MZThdyKAnEuxcD7zhFpF9Kg8Djk0cl5SwXBehm8SRcLE4d0ibuRac8B2VGMEw/640?wx_fmt=png "")  
  
  
扫码关注  
  
小C学安全  
  
获取更多资讯  
  
  
  
  
  
  
  
‍  
  
  
