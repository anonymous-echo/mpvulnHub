#  漏洞扫描工具 -- SBScan   
点击关注👉  马哥网络安全   2025-01-17 09:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAliaic0KIAYzx92YgY0Kbic1ByRdVrsvCicRzOUia0LOEP6Hc86gTVoSmWL3jMtEwpTqZoZV0DLABGSOLw/640?wx_fmt=png&from=appmsg "")  
  
前言：SBScan是一款专为Spring框架量身定制的渗透测试工具，它能够对目标网站执行Spring Boot未授权访问检测、敏感信息泄露检查，以及Spring框架相关漏洞的全面扫描和验证。全面覆盖的敏感路径库：SBScan配备了业界最全面的Spring Boot网站敏感路径库，能够全方位检测网站是否面临敏感信息泄露的风险。指纹识别能力：Spring站点指纹识别：SBScan能够启动指纹识别功能，仅对检测到Spring特征的站点进行深度扫描，以此节省资源和时间。（请注意，无特征站点可能会被遗漏，用户需自行决定是否启用此功能。）敏感路径页面关键词识别：通过识别包含在敏感路径中的关键词特征，SBScan能够对检测到的页面进行精确的指纹匹配，显著提高检测的准确度，减少人工验证敏感页面真实性所需的时间。模块化检测启动：如果用户只关心敏感路径的检测，或者只想要进行漏洞扫描，SBScan允许通过-m参数来指定特定的检测模块。全面的Spring漏洞检测POC集合：SBScan集成了所有Spring相关的CVE漏洞检测POC，是同类工具中最为全面的。无回显漏洞检测解决方案：对于无回显漏洞的检测，SBScan支持通过--dnslog参数指定DNSLog域名，确保只有在DNSLog记录实际出现时，才确认漏洞的存在。精简化输出结果：用户可以通过-q参数来指定只显示成功的检测结果，以此减少不必要的信息干扰。易于扩展的设计：SBScan在设计初期就考虑到了用户的自定义扩展需求，采用高内聚低耦合的模块化编程方式，使得用户可以轻松添加自己的POC、积累的敏感路径和绕过语句，优化检测逻辑。其他支持功能：SBScan还支持单个URL扫描、URL文件批量扫描、扫描模块选择、代理设置、多线程扫描以及生成扫描报告等常规功能。  
安装与使用：  
  
**安装：**  
  
```
MacOS && linux

$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan         # 创建虚拟环境
$ source sbscan/bin/activate     # 激活虚拟环境
$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；
$ python3 sbscan.py --help


Windows

$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan         # 创建虚拟环境
$ .\sbscan\Scripts\activate        # 激活虚拟环境
$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；
$ python3 sbscan.py --help


```  
  
  
  
**使用：**  
  
1、调高探测与扫描并发  
  
```
./SbScan -h 192.168.0.0/16 -wsh 500 --wsp 500

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8H1dCzib3Uibv7m2p9YDPPKnQhS66g1PzOWYfqyh91FjBLj59Bibicfv2LwxJ4zqnZbibs72Fv6iaM4xVj3Wfbria7icNA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
2、端口扫描可以写端口号、端口范围或者常用端口类型  
  
```
./SbScan -h 192.168.188.0/24 -p 80,22,81-89

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8H1dCzib3Uibv7m2p9YDPPKnQhS66g1PzOKIql0J7DiaYslpT31IL9T6ZZeibUx1Vg4DYx7TyS1bDuhRtKuZh6bgOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
3、列出weblogic漏洞对应的poc  
  
```
./SbScan --lpn --fpn weblogic

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8H1dCzib3Uibv7m2p9YDPPKnQhS66g1PzOuooJshCZ15AuLxqWu9sricSqUKKKcU4CjZbMZSdOEtXAZjfSMoay5ibQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
4、列出thinkphp漏洞对应的poc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8H1dCzib3Uibv7m2p9YDPPKnQhS66g1PzOVmsHvrvOtJ0siazEqy4cXYqicp3KictQ6Z0SDRy3sJsJ8ZaLH2I3VmM6g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
下载链接：  
  
https://github.com/shmilylty/SharpHostInfo  
  
如有侵权，请联系删除  
  
****  
**文末福利**  
##   
## 现在已经步入2025年了，不少小伙伴在考虑入行学习网络安全。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAmTHoVHrG8PppyYU8FpGmLJDLOPiax3pqwnq9hFjDSMH4cpYptL3h071PkP0jkoR5ib2Ksfia8VFnicmQ/640?wx_fmt=png&from=appmsg "")  
  
为了帮助大家早日习得网络安全核心知识，快速入行网络安全圈，**给大家整理了一套【2025最新网安资料】**  
**网络安全工程师****必备技能资料包**  
（文末一键领取）**，内容有多详实丰富看下图！**  
  
**Web安全**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFBODrmsTGnPTOibdIT9B5eFLTHVIgWzYafxGAesmYnfzrz52xwV3Bjhw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**渗透测试**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFVKWl2cLRTq7x9haKJerUZNO0YMhiaO8ibN1jjV0qxNLEvRKMfR90eNjQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全面试题**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFgrmaDLaYT1yV5lst9tKC72QrYjd5I8IN7kcOZIZSfQJJz8MdX6a1uA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**代码审计**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFxmUkTNP1iagssZL5zkjID8hibpZsRCj1OnEb4x7ZYWqpiaymSjc8O7vSQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**HVV文档**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFMD4XeWiaQgOBDgFjkQRogf6djmGx3YRcCCSLYGMY1e4DQejgibv7fffQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**红队笔记**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFVZS1mB4MKAo4FoMBGyVSzq38ZXEKJCjZVaTsFtLE7tIJ3zbRWF5xeA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**入门视频**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/O9D0kmTL9EgxtiaXGtk7loXV41e8AXiaORJMhqFbrtcfHvJWTia6ME2oSI9msVYJu79uCicb7foufuibEHaVg32XnWw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NUwbCdTuQQxsJibSZGyA8akP9TVyJfPcpJ4uIZJDj3akRUfv6cNbnksGJQsibq1aH8iaGDic7TvOaSwNGXLdQ8PC9A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**以上所有资料获取请扫码**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlysrbzcCIib4v2X1CYmWSmqMRksricLDELianZ2FIeNqgiak6gcAuvnI9z04QiafMnMFzA9MeMHBKm88A/640?wx_fmt=png&from=appmsg "")  
  
识别上方二维码  
  
备注：2025安全合集  
  
100%免费领取  
  
（是  
扫码领取，不是在公众号后台回复，  
别看错了哦）  
  
  
