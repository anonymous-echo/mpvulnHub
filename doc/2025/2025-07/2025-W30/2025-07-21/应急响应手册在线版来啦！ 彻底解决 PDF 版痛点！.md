> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDIzNDUxOQ==&mid=2247500952&idx=2&sn=65fe3693a54e1c2ff23b1140c0d52d3d

#  应急响应手册在线版来啦！ 彻底解决 PDF 版痛点！  
 独眼情报   2025-07-21 07:20  
  
   
  
## 0x01 简介  
  
大家好，我们是 NOP Team ！  
  
自 2021 年推出《Linux 应急响应手册》以来，我们的两本手册（Linux 和 Windows 版）一直以 PDF 形式免费分发。在帮助大家学习和解决应急响应问题的过程中，我们收到了许多宝贵反馈。但有几个痛点问题始终未能完美解决：  
- • PDF 复制代码较为困难，尤其是涉及分页和缩进时。  
  
- • PDF 中搜索或复制中文有时会出现乱码，或搜索不到。  
  
- • 许多高校老师朋友希望提供 Word 版本，以满足教学需求。  
  
## 0x02 问题解决尝试  
### 1. 复制代码困难  
  
我们尝试将较为复杂的代码单独上传至 GitHub 仓库，并在手册中引用链接，让大家可以直接从 GitHub 下载使用。  
  
我们甚至考虑将所有代码集中到一个仓库中，但对许多用户来说，这仍稍显麻烦。  
### 2. PDF 中的中文困境  
  
这个问题可以说是个旷日持久的难题，我们尝试过多次解决。  
  
本质上，这是因为 Typora 主题中的字体缺少部分中文字符，导致某些字符无法搜索或复制时出现乱码。  
  
为此，我们基于现有主题定制了一套 Typora 主题，解决了大部分中文问题。效果是：绝大多数中文可以正常搜索和复制；少部分中文虽无法直接搜索，但复制后无乱码，且复制内容可被搜索到。  
  
尽管如此，整体效果仍不够完美。  
### 3. Word 版本  
  
针对高校老师朋友们申请的 Word 版本需求，我们均已提供。  
  
然而，我们的手册原本以 Markdown 格式编写，在 Typora 中转换为 Word 后，格式往往一言难尽，基本丧失了原有的排版。  
  
因此，当用户向我们索要 Word 版本时，我都会事先说明这一情况；但对于高校教学需求，我们还是会尽量提供支持。  
  
为彻底解决以上问题，我们决定直接推出**在线版的应急响应手册！**  
  
大家可以随时搜索、复制其中的代码和文字。后续手册更新时，我们也会同步更新在线版本，确保内容始终最新。  
## 0x03 在线版网站地址  

```
https://book.noptrace.com/
```

  
  
  
网站基于 Nginx + MkDocs + Material 搭建，感谢相关技术开发者的贡献～  
  
由于我们目前有两本手册（未来可能更多），为避免大家要记住子域名到底是 
```
book
```

  
 还是 
```
books
```

  
 ，我们还提供了备用地址：  

```
https://books.noptrace.com/
```

  
欢迎大家浏览、使用，并提出宝贵意见～  
## 0x04 PDF 版本地址  
  
在许多应急场景中，大家可能无法访问网络，而且不少用户更偏好 PDF 的便携性。  
  
从 GitHub 仓库免费获取最新 PDF 版本：  
- • **Linux 应急响应手册**  
  
https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK  
  
- • **Windows 应急响应手册**  
  
https://github.com/Just-Hack-For-Fun/Windows-INCIDENT-RESPONSE-COOKBOOK  
  
## 0x05 往期文章  
- [Windows 应急响应手册 v1.3 发布！](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg==&mid=2247502967&idx=1&sn=64d276c8878b4f1e2fa6f5773b2649ee&scene=21#wechat_redirect)  
  
  
- [Linux 应急响应手册 v2.0.1 发布！(含目录)](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg==&mid=2247502770&idx=1&sn=85b3f9c13c78ee814042b282f6fe6e87&scene=21#wechat_redirect)  
  
  
- [OpenForensicRules 发布！](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg==&mid=2247502811&idx=1&sn=bdf64878bb87c64fb898881f5aadd82e&scene=21#wechat_redirect)  
  
  
- [NOPTrace-Configurator 发布！](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg==&mid=2247502819&idx=1&sn=66c9909519c95e1655978d666aba562d&scene=21#wechat_redirect)  
  
  
- [NOPTrace-Collector 发布！](https://mp.weixin.qq.com/s?__biz=MzU1NDkwMzAyMg==&mid=2247502852&idx=1&sn=3d3f29e38705cbb244c6774bf883997a&scene=21#wechat_redirect)  
  
  
-   
  
  
   
  
  
  
