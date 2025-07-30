#  一款对于web站点进行漏洞扫描的打点利器   
spmonkey  安全之眼SecEye   2024-04-15 20:20  
  
点击上方「蓝字」，关注我们  
  
因为公众号现在只对常读和星标的公众号才能展示大图推送，建议大家进行星标  
。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76k4fD8m0rkPrAict2lkdiaUHasZshA7Yibv0OpnNzpPKLRbGBC8ib7Fngn81sYBPpOaObsyU2iceZ4XPicQ/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
# 免责声明  
  
  
**免责声明：**  
该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
  
  
02  
  
# 文章正文  
  
  
Golden-hooped Rod是一款对于web站点进行漏洞扫描的工具。工具使用python语言编写，使用的目录扫描字典均由真实环境而来。使用起来异常便捷。可以对web站点进行漏洞扫描、设置代理、设置线程等。  
### 使用方法  
```
usage: GHR.py [-h] [-u URL] [-f filename] [--upgrade] [--nodir] [--proxy PROXY] [-t THREAD]

options:
  -h, --help            show this help message and exit

GHR 常用参数:
  -u URL, --url URL     url，例：--url http://127.0.0.1/，注：url中不能添加文件名，如index.html、index.php等，如需添加文件名，请禁用目录扫描
  -f file, --file file  批量url文件名，例：--file url.txt，注：文件中的url不能添加文件名，如index.html、index.php等，如需添加文件名，请禁用目录扫描
  --nodir               禁用目录扫描
  --upgrade             更新
  --proxy PROXY         代理设置，例：--proxy 127.0.0.1:10809（目前仅支持HTTP，暂不支持SOCKET）
  -t THREAD, --thread THREAD
                        线程设置，例：--thread 10 默认线程数为：20

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lfTt7cIt4uicOcvraSbm2HunJCNxJpbWzThY5KkvGtpNDpvNGKBPQW3SaUbVXA0VXrdteEpg1KtDw/640?wx_fmt=png&from=appmsg "")  
  
### 单个url运行截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lfTt7cIt4uicOcvraSbm2Hu1djcHB5AVwibqicQBIBntwG9HFyB3j1hBgRx87MaBDUA6GO6UwZew7Ww/640?wx_fmt=png&from=appmsg "")  
### 批量url运行截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lfTt7cIt4uicOcvraSbm2HuG0eSPOnSKQPfIJexBSYyh0u2V2qRDtfMvMn15TOhRf2QdkHsBZJgWw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lfTt7cIt4uicOcvraSbm2HuBE17QYiczSDjnqz6YQIsRgyfLadt0DyZbGjggfaGq1NXqbTq35lYTOw/640?wx_fmt=png&from=appmsg "")  
  
### 报告截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lfTt7cIt4uicOcvraSbm2Hu3bOVddNmvBImvLuQmuSJwKficpUiaMIMtFib2UMo22W3xBowAD6Tcv88A/640?wx_fmt=png&from=appmsg "null")  
  
report  
### 模块库安装  
```
pip install -r requirements.txt
```  
  
回复关键字【  
**20240415**】领取工具  
  
  
03  
  
# 知识星球  
  
  
**【圈子简介】**  
  
**高质量漏洞利用工具、最新漏洞POC/EXP分享社区，日常更新一个0Day/Nday/1day及对应漏洞的批量利用工具，内部POC分享，星球不定时更新内外网攻防渗透技巧等。分享行业最新资讯，交流解答各类技术问题。**  
  
**【圈子服务】**  
1. **Fofa永久高级会员，助力挖洞**  
  
1. **常态化更新最新的漏洞POC/EXP**  
  
1. **常态化更新未公开、半公开漏洞POC**  
  
1. **常态化更新优质外网打点、内网渗透工具**  
  
1. **常态化更新安全资讯**  
  
1. **开放交流环境，解决成员问题**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76kefyoAP2kELVOnW1PJe79111sSF8J3BGRaglm4y5icey31Z8gU90M9Z9KVibXSjn3YAfLnYUhhmr4g/640?wx_fmt=png&from=appmsg "")  
  
  
点个「在看」，你最好看  
  
  
