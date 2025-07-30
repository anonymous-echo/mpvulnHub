> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIyNzc3OTMzNw==&mid=2247485939&idx=1&sn=03c3ffef5a2ae3b4cd0db6c79534f4a3

#  工具分享 | 一款JumpServer堡垒机未授权综合漏洞利用脚本（近期更新）  
tarihub  篝火信安   2025-06-25 07:50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb3cJRXaQcG0XMFzo55tCOgNYdwynprOibLaDibbMibpBWicDWwzTY2aYOdZgw49ibxONGnmbibSqSiar9TWg/640?wx_fmt=png&from=appmsg "")  
  
简介  
  
一款  
JumpServer 堡垒机  
未授权  
综合漏洞利用脚本，支持漏洞  
CVE-2023-42442 / CVE-2023-42820 / RCE 2021，实测能运行，但密码重置和命令执行漏洞利用时会触发报错。  
  
  
支持漏洞  
-  未授权任意用户密码重置 (CVE-2023-42820)  
  
-  未授权一键下载所有操作录像 (CVE-2023-42442)  
  
-  未授权任意命令执行漏洞 (RCE 2021)  
  
安装  
  
python3 -m pip install -r requirements.txt  
  
  
使用指南  
  
python3 blackjump.py {reset,dump,rce} -h  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb3cJRXaQcG0XMFzo55tCOgN6jmoUKMKZxNEoxhguYE2H1ZertVdTgCn1iatSMLYwGhSbhE8wBicyEyg/640?wx_fmt=png&from=appmsg "")  
  
1、CVE-2023-42820  
  
如果知道目标的用户名和邮箱可以指定 --user 和 --email 参数  
  
python3 blackjump.py reset https://vulerability  
  
![img.png](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb3cJRXaQcG0XMFzo55tCOgNxV7BqW0qz5Xj24tB2dLcQxjRpcRcAB9maN3zrHF6n4bPuhHHnbVGBA/640?wx_fmt=png&from=appmsg "")  
  
2、CVE-2023-42442  
  
output/ 目录下的 <uuid4>.tar 文件扔进 jumpserver播放器播放即可  
> jumpserver播放器：  
> https://github.com/jumpserver/VideoPlayer/releases  
  
  
python3 blackjump.py dump https://vulerability  
  
![img_1.png](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb3cJRXaQcG0XMFzo55tCOgNVv59tGwcr7jIo1qx90DoBuzicMdKJWGGLG8FcUdVn96vHtL3iaKpA3Ow/640?wx_fmt=png&from=appmsg "")  
  
3、RCE  
> https://github.com/Veraxy00/Jumpserver-EXP (RCE 2021 漏洞在其基础上优化部分情况命令执行失败或获取不到资产问题)  
  
  
python3 blackjump.py rce https://vulerability  
  
![img.png](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb3cJRXaQcG0XMFzo55tCOgNrsQjicYGuWaQaTR5Ricjak7ZQH4Vjks2qHykzLRO1q85YXiaAuwFU9dqQ/640?wx_fmt=png&from=appmsg "")  
  
  
## 免责声明  
  
本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标使用。  
  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CQf7uHzmVb3icxXWABkpMvXDJ1aDF6RgkCFLMvzDgLEx7jjY4A1n7yTEc2AZmg5CFFoeHJLb3AiblNHRLVFBqlfw/640?wx_fmt=gif&from=appmsg "")  
  

```
下载地址进入公众号回复关键字【20250625】获取项目链接
```

  
  
  
