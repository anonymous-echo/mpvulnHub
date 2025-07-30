#  【漏洞预警】Telegram Windows客户端可执行文件限制不当RCE漏洞   
cexlife  飓风网络安全   2024-04-15 20:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00PZQ5FHk9ejibJSuv8Ckbg9ibAWgoIcn3tPS8Wjmxc3n6YIQrQIASlCAlRURuib0Xq4hb3GGHt8XWmA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Telegram是提供开源客户端的跨平台即时通信软件,在其客户端中通过黑名单限制Windows下可执行文件后缀,由于黑名单列表错误拼写了python zipapp后缀pyzw、遗漏lua可执行文件后缀wlua和lexe,在telegram中传递该类型文件不会出现安全提醒,同时可利用机器人API伪装文件为视频传播,诱导用户点击,导致利用受害用户环境中的python、lua执行任意代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00PZQ5FHk9ejibJSuv8Ckbg9yeX57D80tGTR6gecNH8KatdpH078D9Ip159ET1rZ78qdfibrrh3gf5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00PZQ5FHk9ejibJSuv8Ckbg94cnqib887sFVQue9MicSmXKhFzgWEysVf3TdR1cdhYZw047rc2sviaNiaw/640?wx_fmt=png&from=appmsg "")  
  
**影响范围:**  
  
telegram(-∞, 4.16.6]**修复方案:**建议临时使用Web端telegram或禁用pyzw、wlua、lexe文件默认打开**参考链接:**https://github.com/telegramdesktop/tdesktop/pull/27737/commits/effad980f712cd1a4e8cee4fca42193fe5a612dehttps://github.com/telegramdesktop/tdesktop/pull/27744/commits/a78e6ff8af3fcc979eaf8207872f0fad595584a4  
  
