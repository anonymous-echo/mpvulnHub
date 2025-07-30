#  info_scan 自动化漏洞扫描系统   
三沐  三沐数安   2024-08-05 08:30  
  
##   
## info_scan 简介  
  
  
自动 漏洞扫描系统。  
  
包括IP基础信息探测模块：(位置、属性、操作系统、端口、绑定的域名、公司名称、公司位置信息、网站标题、CDN信息、绑定网站指纹、子域名)，  
  
漏洞扫描模块：(weblogic、struts2、nuclei、xray、rad、目录扫描、js链接扫描、端口扫描、调用威胁情报抓取历史绑定url、网站指纹、信息泄露、vulmap、afrog、fscan、DNS日志、shiro、springboot、服务弱口令扫描、识别重点资产)  
  
资产管理模块：(资产发现、资产展示、CDN检测、存活检测、资产回退、重点资产识别)，单个扫描模块报告支持在线预览，总报告支持下载和预览。  
## 注意事项：  
  
保证系统正常运行需要2个项目：  
  
info_scan 漏洞扫描主系统  
  
batch_scan_domain：xray+rad批量扫描，通过info_scan进行控制  
  
**使用说明**  
1. 安装python3+MySQL数据库  
  
1. 建议安装nginx反向代理web服务，部分接口会出现查询超时情况，可通过nginx控制超时时间，也可直接通过flask直接访问，只需修改scan_main_web.py和dirscanmain.py最后一行IP部分  
  
1. 不要修改目录，容易报错，将info_scan和batch_scan_domain部署到服务器的/TIP/目录下，  
  
1. 将/TIP/info_scan/static/js/common.js中的x.x.x.x替换为vps ip，替换命令(:%s/x.x.x.x/vps_ip/g)  
  
1. info_scan系统相关配置在/TIP/info_scan/config.py文件配置  
  
1. 系统使用前需点击解锁按钮进行解锁  
  
1. 系统主要功能分为三类，第一是对IP进行基础信息探测，第二是对URL进行 漏洞扫描，第三是对URL数据进行处理  
  
1. 建议部署到Ubuntu系统下，不支持Windows系统  
  
1. 系统设计初衷就是集成开源 漏洞扫描器，让测试人员通过网页一键完成扫描，提升工作效率  
  
1. 需要通过pip3安装requirements.txt中的模块  
  
1. 建议先执行 python3 scan_main_web.py（主系统）和python3 dirscanmain.py（目录扫描子系统），确保系统运行正常后在利用bash server_check.sh进行管理  
  
1. nginx相关配置文件在nginx_conf目录下，将nginx.conf放到/etc/nginx目录下，将dirscan_nginx.conf和infoscan_nginx.conf放到/etc/nginx/conf.d目录下，执行nginx -t检查配置文件是否正确  
  
1. 系统需在开通以下端口：15555、16666、17777、18888、19999、3306  
  
## 项目目录结构  
  
****  
├── /TIP│   
  
├── info_scan│   
  
├── batch_scan_domain  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49AibyYHeUUEW1ppc51N7RIdYbJtF1Pyv5XDX8yPUyl78NX1oA2WMXzYQ/640?wx_fmt=png&from=appmsg "")  
  
##   
## 截图  
  
****  
**程序文件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49813qQ78eLba1AygerWtL3VXoW71Se6cFeCxpf0iaDDnSASkzgz4iabOw/640?wx_fmt=png&from=appmsg "")  
  
**服务启动参数******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49G1VibJFkibicZwciaZdUicD2IHZKmvnYOOQQ8gcUE3Dcdpsg7w9KXyhPpag/640?wx_fmt=png&from=appmsg "")  
  
**部分功能截图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav498pY2btI561riaVD2QSQHkItKAzicOBIhiauHjvSUN44zhDJiajp8rlYPSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49ztkfs714l9RpY8aiaxZ08NL7j1Yc6eua7fANibeNuYzbz5M7kOwic5RKA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49DgXGHzvu6EKRl4x88qia62EzyWHGmyjbrp6Rm2jW0g6JvqbGOfz8OhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49lx7U0hZMETUBlRvIgDZuiaicMx1RPU2d9v6re6F8havIBEppsRogL6Fg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49Z0HKibXQDSVAD0MLr12icp8G3nfl6G2eaXCIqNY0YY8OEhWLn6pyIiaPA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞报告******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49TPIfTqeoz1yWBUxuSvUcG5dwVkIPRVGEDzc1Yun9Hp99iaD2h2yqR9w/640?wx_fmt=png&from=appmsg "")  
  
******资产发现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49eIHMLRxeUt6PPH1AQUcx6ic9QgqdiaFm8gpCsPRrLVvFYnJwbYRP6WVA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav499Hf0tWq5Q6D0wFcJwEgsuiao2rR0Mj7b5r5O5p4pE4PdliciaTicMjVEtg/640?wx_fmt=png&from=appmsg "")  
  
**弱口令扫描******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49M0upGLD78BktKUIxRgTRFHtOqs5LoTWDiboUrSDRG5ebjbxQgBwXiaibg/640?wx_fmt=png&from=appmsg "")  
  
**总报告在线预览******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav4914ZQ3ATOH0dodsOicydWfHatuK391MvB4wAnodJXpsgx0I3Yt7gQe0A/640?wx_fmt=png&from=appmsg "")  
  
**一键扫描重点资产漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jLATCxHDB3Ib0e6HMuav49hBiajeU293Y41QuWnWGjHnUiaWx1qZ7HKqmM2quz4XicdWlF7S2fTXCwg/640?wx_fmt=png&from=appmsg "")  
## 项目地址  
  
**GitHub：https://github.com/huan-cdm/info_scan**  
  
****  
  
