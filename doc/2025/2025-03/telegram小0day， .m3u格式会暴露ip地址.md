#  telegram小0day， .m3u格式会暴露ip地址   
 独眼情报   2025-03-30 14:42  
  
影响不大，反正都是暴露的代理ip地址。🐶  
  
带有 .m3u 扩展名的消息可能会泄露您的 IP（Telegram 桌面版/Windows）。Telegram 对 .m3u8 发出警告（“打开此文件可能会暴露您的 IP 地址...”），但对 .m3u 则不发出警告。 注意：.m3u 是一种简单的基于文本的播放列表格式  
  
![图像](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTWFqBicm9yPdYtia9yPSndbicOC6icuaJhVcMB1AW5WnibQdgeEIaCeuziaDbibDibs2BorbK4Adh50JIJ0A/640?wx_fmt=jpeg&from=appmsg "")  
  
NTLMv2 哈希？ Telegram 似乎忘记为这种文件类型添加警告信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTWFqBicm9yPdYtia9yPSndbicM8OTL7ric99rVibdX9s72SuTkA8CX2xlwDpib03R2YkAC7ago5ibvxicj4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
