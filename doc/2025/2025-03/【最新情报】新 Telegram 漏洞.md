#  【最新情报】新 Telegram 漏洞   
原创 visionsec  安全视安   2025-03-08 17:59  
  
**声明**  
**：该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。**  
  
发现新的 Telegram 漏洞 EvilLoader。这使得攻击者可以将恶意 APK 伪装成视频。它仍未打补丁，可在 Android 11.7.4 版 Telegram 上运行。甚至有证据表明，它已在地下论坛上出售，供人们随意使用，并可用于安装间谍软件、勒索软件和其他恶意软件。  
  
攻击者可将恶意 APK 伪装成视频，在 Android 版 Telegram 11.7.4 上执行，目前仍未发布补丁。  
  
 该漏洞已出现在地下论坛，供不法分子随意利用，可能被用于 勒索软件传播 及 恶意软件安装。  
  
  
![图像](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Pf9NC3AaQF5uU2K69ebNZiaBn7XOZo06emy7dauUHiachERqlzydmILzoh9JURXbK7Z7mzNOmYPThJez37ayOzdw/640?wx_fmt=jpeg&from=appmsg "")  
![图像](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Pf9NC3AaQF5uU2K69ebNZiaBn7XOZo06eLJwr9KlGmfPAUxjop9hSAq5QiaUfKVibmnMmpmk1RLMniciblHrHXjfbEw/640?wx_fmt=jpeg&from=appmsg "")  
  
只从漏洞角度看上去还好， 视频打开的是一个content://  打开html 诱导下载apk安装 ，还以为是直接文件覆盖。  
  
