#  工具分享 | nuclei管理工具＋9w poc不想要嘛？   
原创 Perlh  不秃头的安全   2024-11-28 00:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVNCXqrL9k0r2icauIbCEBEls8X0kfM78frUZBL3ZSZKZlICQlev704WAdTLlWPZ0taFhvEm1mr3Lg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******nuclei管理工具＋9w poc不想要嘛？******  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。  
  
还在学怎么挖通用漏洞和src吗？快来加入星球  
  
由  
于微信公众号推送机制改变了，快来  
星标不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fXy8gHzKiaBoATGQ8tpR3ahROtv4Aby7ehiafuS9DyQ6ESNKa1IP4YJpcEbDB3BrHMAQdHYwONFURWQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
# 后台回复 241128 ，获取工具下载地址与poc。  
##   
## nuclei模版管理工具  
  
  
由于没找到一款比较好用的poc管理器，作者自己开发了这个，仅提供下载安装包。  
## ✨ 功能  
  
-  实现nuclei poc管理的桌面应用，对nuclei模版的增删查改操作  
  
-  支持查看nuclei模版请求响应包  
  
-  支持MacOS、Windows和Linux操作系统  
  
-  使用全新nuclei v3检测引擎  
  
-  兼容yamlv2和yamlv3 nuclei template  
  
-  实现多任务、并行扫描  
  
-  支持使用自建的nuclei DNSLOG服务器  
  
-  支持http代理（http、https、socks5）  
  
-  支持主题切换  
  
-  支持多种nuclei模版导入方式  
  
# 快速使用  
## poc模版导入  
### 手动导入  
###   
#### macos  
  
对于MacOS和Linux，初次打开App会在家目录生成模版文件夹  
```
ls /Users/$USER/.wavely/templates # macos
ls /home/$USER/.wavely/templates    # linux
```  
```
```  
#### windows  
  
会在wavely.exe的同级目录下创建.wavely/templates，将poc放入此文件夹中（请开启显示隐藏文件/文件夹）  
#### 导入  
  
  
如下图所示 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj14CbgGOOmAt7erDPSSwHpygAX0SycCPAd6RIpJezCz3sjFFQnkmkt1A/640?wx_fmt=png&from=appmsg "")  
  
###   
### App指定路径导入  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1o4jG0JLRV5JQjvlianH0zfErKRticVdvqcEI5ryd14wBcRjyYgjhIbdg/640?wx_fmt=png&from=appmsg "")  
###   
### 模版管理  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1I14B9vv9uQfsrY0QNT0wW2411bRwaibNOcql9GlLZRa3TDD3icZz0oMg/640?wx_fmt=png&from=appmsg "")  
###   
### 扫描  
###   
  
选择thinkphp的poc进行扫描 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1SKbs9qNzAQvNZicls2fHsejia6vNH8drGMK0viawOpPRhNLJw3ZyjMv7g/640?wx_fmt=png&from=appmsg "")  
 扫描结果 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1gY9WeBtUEATmIswISItfRv8noicE1zdicqZV6d2LQJddnSO8jOtORFfg/640?wx_fmt=png&from=appmsg "")  
 可复制扫描结果  
###   
### 编辑nuclie模版  
  
  
编辑模版 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1dbNS3xaIfu0l0Efk8Bs6Ptx3qlG1VyyRcmes8B3bAds5nkOWcDzdBA/640?wx_fmt=png&from=appmsg "")  
 匹配请求包 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1yz3aljbx3zSa9iaOJbaTSbeofVZoZEPJ5SPZ8UWxkic750Yibhw6epzcg/640?wx_fmt=png&from=appmsg "")  
 匹配响应包 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1H2nFjf272mAoKVDH41LoGMJlhy4jGzQbkDYQAN8DdEvZtC5yy96hYQ/640?wx_fmt=png&from=appmsg "")  
  
###   
### 添加Nuclei模版  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1Ess8g8gUIRciaWp3SRUKve42Oo30KEwpEfk7iaCa9rkw9AJ8OKJ5f8Jw/640?wx_fmt=png&from=appmsg "")  
###   
### App设置  
  
  
主题 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1icRMjRQ5k5NWfLQWicorNaROSFSSr6jCGfyRS5ZQUz1PMwOKQLOiawtLg/640?wx_fmt=png&from=appmsg "")  
  
  
代理 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1p5cnMiaOKSmA7bC89LxvamJV2dsNQT8zWQGyWr9IEXmPI2IynzZ75sw/640?wx_fmt=png&from=appmsg "")  
  
  
扫描 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1ibfy8OP1ZqxagHj9j8AibRHAicqO9prwhqBd9nKtaOVl0dotVicMQTSc5w/640?wx_fmt=png&from=appmsg "")  
  
  
模版导入 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1Bia53DP9sPjiaicOb76bBysibOMW8nrpgIxE4lSh6FCdpqmGr6zOnbXXQg/640?wx_fmt=png&from=appmsg "")  
  
  
### 11w nuclei poc  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fX3Z6uOjcyKShamEPic77Mj1YCSx9rYzsFniaZkwHCSQwYaA5cD5xUSyYibPK2lLzcnfgay0Lph1fbLg/640?wx_fmt=png&from=appmsg "")  
  
导完在8.6w+![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fUicZRRiar5pBRr2FcJHKQTQogCicibf4sNLxibcZatuibyicwFDtfcoJTCwQtfkZYG73aoHwaUJDokFYXmg/640?wx_fmt=png&from=appmsg "")  
  
  
****  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
**关注福利：**  
  
回复“  
google工具" 获取 google语法生成工具  
  
回复“  
小程序渗透工具" 获取 小程序渗透工具  
  
回复“  
暴力破解字典" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西（  
还在学怎么挖通用漏洞吗快来加入），16个专栏会持续更新~  
**提前续费有优惠，好用不贵很实惠**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fXBicaFjsFRxEWjpE7PbIIxiaFkGMtj0VicSlLEckNcd8nib4fPDBic4skgfalZicyeGT1Q2MAjY3aA75DQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**交流群**  
  
加我联系方式拉交流群~  
  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，  
CISP  
、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理......  
巨优惠  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
