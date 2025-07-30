#  ThinkPHP开发框架曝高危漏洞，需紧急修复！   
原创 微步情报局  微步在线研究响应中心   2022-12-09 16:40  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/fFyp1gWjicMKfKRFs38NM1VwWwgdcibkbZDR4HSKNiboI5RjPvcFIlraPg33FWhm9sz0ZAsdFJspp4l3icRyNE7bQA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
01 漏洞概况   
  
  
  
微步在线通过“X漏洞奖励计划”获取到ThinkPHP开发框架命令执行漏洞的0day相关漏洞情报，攻击者可以通过此漏洞实现任意命令执行，导致系统被攻击与控制。该漏洞已在9月25日的V6.0.14被修复。ThinkPHP 是一个免费开源的，快速、简单的面向对象的轻量级PHP开发框架 ，创立于2006年初，遵循Apache2开源协议发布，是为了敏捷WEB应用开发和简化企业应用开发而诞生的。并且拥有众多的原创功能和特性，在社区团队的积极参与下，在易用性、扩展性和性能方面不断优化和改进，已经成长为国内最领先和最具影响力的Web应用开发框架，众多的典型案例确保可以稳定用于商业以及门户级的开发。  
  
**自查检测：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLrAEfHajBlJpqhvJf3SxH9W8G6TTiaXJl3HDOsqKIuwL4L9BW6hdpAXVECB16dS6YLvZkWUjAZs4A/640?wx_fmt=png "")  
  
  
  
**此次受影响版本如下：**  
<table><tbody style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 18.3pt;visibility: visible;"><td style="margin: 0px;padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1pt;border-style: solid;border-color: black;max-width: 100%;visibility: visible;overflow-wrap: break-word !important;box-sizing: border-box !important;" width="207" valign="top" height="18"><p style="visibility: visible;"><strong><span style="color: rgb(0, 0, 0);font-size: 14px;letter-spacing: normal;text-decoration: rgb(0, 0, 0);">ThinkPHP开发框架命令执行漏洞</span></strong></p></td><td style="margin: 0px;padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-width: 1pt 1pt 1pt medium;border-style: solid solid solid none;border-color: black black black currentcolor;max-width: 100%;visibility: visible;overflow-wrap: break-word !important;box-sizing: border-box !important;" width="242" valign="top" height="18"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;clear: both;min-height: 1em;visibility: visible;text-indent: 0em;box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;visibility: visible;">是否受影响</span></strong></p></td></tr><tr style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 18.6pt;visibility: visible;"><td style="margin: 0px;padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-width: medium 1pt 1pt;border-style: none solid solid;border-color: currentcolor black black;max-width: 100%;visibility: visible;overflow-wrap: break-word !important;box-sizing: border-box !important;" width="228" valign="top" height="18"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;clear: both;min-height: 1em;visibility: visible;text-indent: 0em;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(0, 0, 0);font-size: 14px;letter-spacing: normal;text-decoration: rgb(0, 0, 0);">v6.0.0 ~ v6.0.13</span><span style="color: rgb(0, 0, 0);font-family: 黑体;font-size: 10.5pt;visibility: visible;"><span style="color: rgb(0, 0, 0);font-size: 14px;letter-spacing: normal;text-decoration: rgb(0, 0, 0);visibility: visible;"></span></span><span style="font-size: 14px;text-indent: 0em;font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"></span></p></td><td style="margin: 0px;padding: 0cm 5.4pt;outline: 0px;word-break: break-all;hyphens: auto;border-width: medium 1pt 1pt medium;border-style: none solid solid none;border-color: currentcolor black black currentcolor;max-width: 100%;visibility: visible;overflow-wrap: break-word !important;box-sizing: border-box !important;" width="242" valign="top" height="18"><p style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;clear: both;min-height: 1em;visibility: visible;text-indent: 0em;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;visibility: visible;">是</span></p></td></tr></tbody></table>  
  
02 漏洞评估   
  
  
  
**公开程度**  
：PoC未公开  
**利用条件**  
：无权限要求**交互要求**：0-click**漏洞危害**：高危、命令执行**影响范围**：ThinkPHP开发框架命令执行漏洞  
  
03 修复方案   
  
  
  
1、获取官网V6.0.14的补丁包，进行升级即可。  
  
https://github.com/top-think/framework/releases/tag/v6.0.14  
  
2、微步在线TDP已支持相关漏洞检测，对应规则ID为：S3100031334。  
  
3、微步在线X企业版已支持相关漏洞检测：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLrAEfHajBlJpqhvJf3SxH98myGBbNWfxQDd3eeLgvs1Cylq65gB98lUYHBGD3jneM3ibYLAX0p2lQ/640?wx_fmt=png "")  
  
### 04 时间线 2022.09 微步“X漏洞奖励计划”获取该漏洞相关情报2022.09 漏洞分析与研究2022.09 TDP支持检测2022.09 厂商发布补丁2022.12 X企业版支持检测2022.12 报送监管2022.12 微步情报局发布漏洞通告  
###   
  
点击下方名片，关注我们  
  
第一时间为您推送最新威胁情报  
  
  
  
