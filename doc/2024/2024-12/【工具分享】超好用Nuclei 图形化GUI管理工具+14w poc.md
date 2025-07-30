#  【工具分享】超好用Nuclei 图形化GUI管理工具+14w poc   
原创 Mstir  星悦安全   2024-12-26 04:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/J7IPO94Qju9FTugulOKxWfnjYuhwWcBzRf5mLyA8anmiaoXkQZgtANooNPL4hbJicp0lOoibMDpkIQiaO88d4psQCw/640 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jMdTfMECSV10PfPI4lwN5vCxJ3kc2FoHl7zfNk7cWapbmejhVzicyLPKdLnU7V3u8GwZ0qb8aed1HW6DtG3ic5dw/640 "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/J7IPO94Qju9FTugulOKxWfnjYuhwWcBzNp3yfnwWrcF0DcKr27Zc4PQCiaoyhHg7ibojqgfRjictIicb6YtY1emIaw/640 "")  
  
## 0x01 Wavely介绍  
  
wavely是一个好用的nuclei GUI POC管理工具，且支持诸多功能，能实现对目标站点的多态化扫描，且版本更迭较快.   
  
**下载地址在文末，可直接拉至底部获取**  
  
```
 实现 nuclei poc 管理的桌面应用，对 nuclei 模版的增删查改操作 支持MacOS、Windows和Linux操作系统 实现选择多个POC、多个扫描任务和多目标并行扫描 支持自定义 DNSLOG服务器，支持自定义扫描速率和支持http代理（http、https、socks5） 支持查看 POC 匹配到的请求包和响应包 使用全新nuclei v3检测引擎，兼容 yamlv2 和 yamlv3 nuclei template 支持 POC 编辑器主题切换 支持多种 nuclei 模版导入方式 支持 nuclei 模版去重导入 支持国际化（支持简体中文和英文） 支持手动停止扫描任务 支持配置持久化 支持API扫描（支持带目录扫描，如：http://target.com/api）
```  
  
  
安装:  
  
```
MacOS下载相应压缩包并解压，解压文件夹中包含 Wavely.app和 Applications文件夹。将Wavely.app拖到Applications文件夹中终端执行:sudo xattr -d com.apple.quarantine /Applications/Wavely.appWindows使用 Wavely-amd64-installer.exe.zip 安装程序进行安装
```  
  
  
POC导入:  
  
```
在App中导入POC（带POC去重）点击从文件夹中导入按钮，选择nuclei poc文件目录。
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6KX6Guc9CEW616mRkYn9iaQicAOKFicJrTOicq6fLRFr4ibBQ4GricwUsWeog/640?wx_fmt=png&from=appmsg "")  
### 快速使用:  
  
以扫描thinkphp漏洞为例  
  
1、搜索 POC 并扫描  
  
不选择poc，则对搜索结果进行全扫描  
  
选择poc后，则对选择的poc进行扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6E2iaAP0h4Hs37MJ80SsIicZVQOTzLIaGr4Uh35cwftG7C7kn4VlCm4zA/640?wx_fmt=png&from=appmsg "")  
  
2、添加目标  
  
按行添加目标  
#####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6USKmPa7CTA6jo1cy6QJYHojB5QoYj1JfFet40Ss8WNMBolHpd4zdJQ/640?wx_fmt=png&from=appmsg "")  
  
3、扫描结果  
  
点击POC ID可跳转到POC编辑界面  
#####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6faC6ZV1gcSw1CTVbNpibqO5zVmkh0uQ2D666LAxcHo6pTJ8WVFUIuvg/640?wx_fmt=png&from=appmsg "")  
  
4、POC测试  
  
对于测试匹配到的POC，可显示请求响应包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6QNZURmX9Dr2z0LbTBOr3TbINkyVkWv1GzvXwUJpqSwDRJZJVthFBAg/640?wx_fmt=png&from=appmsg "")  
  
5、添加Nuclei模版![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6Oef2vGJVHcKgXUexIAlJcuHXFTTbSMA8YctlcrKhTYTAJSZXX1MwiaA/640?wx_fmt=png&from=appmsg "")  
  
  
6、App设置  
  
通用设置  
  
可切换POC编辑器主题  
  
选择语言  
#####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6ldKalE8vjy7ib7dBKCWayRfJAAVb8F36WA5gCvrPnFAJBaicdl4E92ww/640?wx_fmt=png&from=appmsg "")  
  
网络设置  
  
添加HTTP代理  
######   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6DeO6icaI7Y6y8SfuLCV8DXdxNA95Ky5V5RF54HC6B9w3LumBHUW3NlQ/640?wx_fmt=png&from=appmsg "")  
  
扫描设置  
  
POC扫描参数设置  
  
设置扫描并发数  
######   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6DhficyaIKIlf3rtWokIcmWAPPUcY2Fr9uzR7DeM8cKWd3odKCW5NbOA/640?wx_fmt=png&from=appmsg "")  
  
模版设置  
  
更新数据库  
  
导入模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6JXTI1me3WFJala9YhOt8dibqvZR7NrkLS6xpveFKicsWspZjPibuhiaTqg/640?wx_fmt=png&from=appmsg "")  
  
  
常见问题:  
  
Windows启动时闪现弹出命令框 为正常现象，不影响App的功能  
  
Macos 无法打开App 由于没有使用apple证书签名app，可能会提示解除安全验证：软件显示禁止符号 或 无法验证软件身份 或 提示已损坏故不能正常打开，请参考：  
  
方案1 执行如下命令即可：  
```
sudo xattr -d com.apple.quarantine Applications/Wavely.app
```  
  
方案2  
```
chmod 755 /Users/$USER/Desktop/Wavely_darwin_arm64_1.5.2.app/Contents/MacOS/Wavely
```  
  
## 0x02 Nuclei_14w POC  
  
整理了14w+的Nuclei POC，直至今日的最新漏洞详情，其中有几大分类，并且可直接导入到上述工具，并直接调用扫描使用.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6ESUV4g0uT9ibcYwnAVo4m33FhK3WDN8nYfxg8tfRIEyibyoXTWzwFibkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM61KQP18oLRZEFUaUvSSK8Na2xZIApLWAibyv7GibAP0e1AKr8B7yyIbJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6bj1ho80RcdXBNUPwtggJjZJqIvnMgicVOf7OLft5okm9udciaDNIJZZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ebwBhbwsBEaMlGlibpawicM6SvmLIPeveS3ibCibfGBTE9Nt1nfZKww9ibQg8M0H3YcRHBlV4R8KLDboQ/640?wx_fmt=png&from=appmsg "")  
  
工具及POC都已整理好，放至下方.  
## 0x03 工具+POC下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**工具及POC关注公众号发送 241226 获取!**  
  
  
  
****  
**进公开群，代码审计，众测，驻场，渗透测试，攻防演练，CNVD证书全网最低价+VX: Lonely3944**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5erbVnIkcnTFIEZy9wXJARfhbPBGic08dIfyq6cCbZdhlLkQETGMqZfcZ4FxH5meYTWZAReibE9ZZcA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5erbVnIkcnTFIEZy9wXJARfGm5tc2via1EPictNibZVv7KiaQ3fIQQzxTaJibWDFmw6QaNzYicxTR3ye93g/640?wx_fmt=jpeg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
