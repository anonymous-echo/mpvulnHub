> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzYyNzQ1NA==&mid=2247485618&idx=1&sn=0c172c8218bd712fd7319c25ea282f8a

#  速速更新！WinRAR 又又又出漏洞了！  
原创 红队安全圈  红队安全圈   2025-06-26 03:58  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2K9ohfEv3JP2mYJZmoFqadibP2NXm4ndPJ4BsaJLtbVvtsl3EYw8feSrIAFDTC9v6MaWm7MfNzJExg/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
   
  
**CVE-2025-6218**  
，距离上次发文WinRAR出现安全漏洞才过去两个月，现在又爆出一个可导致远程代码执行的漏洞😓，全球超5亿用户的电脑正面临风险！攻击者只需发送一个伪装成报表、合同甚至表情包的压缩包，就能在你的电脑里种下病毒、勒索软件甚至远程操控程序  
  
   
### 漏洞概述  
  
**CVE编号**  
: CVE-2025-6218  
**威胁等级**  
: 高危 (CVSS 7.8)  
**影响范围**  
: WinRAR Windows版本 ≤7.11  
**漏洞类型**  
: 目录遍历→远程代码执行(RCE)  
**受影响用户**  
: 全球约5亿Windows用户  
### 漏洞原因  
  
WinRAR处理压缩包内文件路径时存在逻辑错误，攻击者可构造包含相对路径序列(如 ../../Windows/Start Menu)的恶意文件名，解压时，文件被释放到预期目录之外的系统关键位置(如启动目录、系统文件夹)，绕过安全限制  
  
   
  
### 攻击场景模拟  
  
☑️ 你下载了"2025年度薪资调整方案.rar"  
  
☑️ 解压时恶意文件被释放到系统目录而非用户指定目录  
  
☑️ 电脑重启后自动执行恶意脚本  
  
   
### 影响范围  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">受影响版本</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">安全版本</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">WinRAR ≤7.11</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">WinRAR ≥7.12 Beta1</span></section></td></tr></tbody></table>  
### 修复方案  
##### 1. 官方补丁  
- • 立即升级至 WinRAR 7.12 Beta1  
  
- • 企业用户建议通过组策略强制部署  
  
-    
  
>> https://www.rarlab.com/download.htm  
  
  
   
  
##### 2. 临时缓解措施  
- • 禁止以管理员身份运行WinRAR  
  
- • 设置压缩软件为低权限运行  
  
- • 部署EDR监控异常解压行为  
  
- • 启用Windows审计日志(EventID 4663)  
  
### 3. 替代方案  
- • 7-Zip (v23.01及以上)  
  
- • Bandizip (v7.29及以上  
  
-   
   
  
### 结语  
  
网络安全就像戴口罩——平时嫌麻烦，出事哭断肠！赶紧转发给用WinRAR的同事/家人，你的一次分享，可能拯救TA价值10万的毕业论文/机密合同/珍藏照片！💪  
  
   
  
欢迎关注   
红队安全圈  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
  
