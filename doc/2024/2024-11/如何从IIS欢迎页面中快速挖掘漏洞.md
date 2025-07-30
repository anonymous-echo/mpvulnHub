#  如何从IIS欢迎页面中快速挖掘漏洞   
原创 骨哥说事  骨哥说事   2024-10-31 23:01  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 文章原文：https://gugesay.com/archives/3567  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
# 信息收集  
## Google dork  
```
intext:IIS Windows Server site:*.yourtarget.com
inurl:”IIS Windows Server” site:*.yourtarget.com
intitle:”IIS Windows Server” site:*.yourtarget.com
```  
## 子域收集  
  
subfinder -d target.com -all -recursive -o sbfdr_r1.txtsubfinder -dL sbfdr_r1.txt -all -recursive -o sbfder_r2.txtassetfinder -subs-only target.com | tee ast_target_subs.txt  
## bbot  
  
bbot -t target.com -f subdomain-enum -rf passive -o bbot_target_subs.txt  
## amass  
  
amass enum -d target.com -o target_subs_normal_scan.txtamass enum -active -d target.com -o target_subs_active_scan.txtamass enum -passive -d example.com -o target_subs_passive_scan.txt  
  
当然子域收集工具还有很多，选择更多的工具，收获也会更多。  
# 寻找 IIS 欢迎页  
  
完成子域收集后，就可以使用httpx命令来查找存活的 IIS 欢迎页了：  
  
httpx -l final_subs.txt -sc -td — title  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnvyPLjJS9YRJAwYAIuy8L5xCLlatqFrX62vD6d0jpniaXyDbSBPgDfHy8zwkIyialoSDiaP7eaRicjOQ/640?wx_fmt=png&from=appmsg "")  
## Burp插件  
  
习惯用Burp的同学，可以使用IIs Tlide Enumration Scanner插件，来一键帮你完成扫描。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnvyPLjJS9YRJAwYAIuy8L5gOLcwQachCTmWjVyU7r3ICib8cPCqN72UCJgKSePyfYmF4Ua9tusVpw/640?wx_fmt=png&from=appmsg "")  
  
扫描结束后，可以在下方看到相应的扫描结果。  
## 短文件名扫描  
  
推荐使用shortscan这款开源工具，安装如下：  
  
go install github.com/bitquark/shortscan/cmd/shortscan@latest  
  
使用也很简单：  
  
shortscan http:target.com -F  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnvyPLjJS9YRJAwYAIuy8L5hZO1jJ4sGoYibibywaiaXZFjcicZ6tBRf5OXmHvnQPcmib1OSzYejgwtLmg/640?wx_fmt=png&from=appmsg "")  
  
当然，短文件名工具也有不少：  
  
https://github.com/irsdl/IIS-ShortName-Scannerhttps://github.com/sw33tLie/snshttps://github.com/lijiejie/IIS_shortname_Scannerhttps://github.com/0xRTH/IISRecon  
  
根据个人喜好选择食用即可。  
  
你学会了么？  
  
[IIS欢迎页的安全隐患：从源代码到LFI的攻防之道](http://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650259777&idx=1&sn=225065423a6b3d3f23e1905f18df2eff&chksm=be92aac589e523d374d56afd6775f8807457360008f559c53c82350c7c51ea0e01afbb898303&scene=21#wechat_redirect)  
  
  
**加入星球，随时交流：**  
  
****  
**（前50位成员）：99元/年************（后续会员统一定价）：128元/年******![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～****====正文结束====**  
  
  
