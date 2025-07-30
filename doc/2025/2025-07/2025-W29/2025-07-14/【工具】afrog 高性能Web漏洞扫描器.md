> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUzODU3ODA0MA==&mid=2247490678&idx=1&sn=2bc385ae9c50e43f2cb6a1d804168153

#  【工具】afrog 高性能Web漏洞扫描器  
原创 NOVASEC  NOVASEC   2025-07-14 15:56  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZABNHic6I2k8vayq06GiaN0PjuJtkhP7vxlCDuQbSnofqkMWgjtQCZqKTrdm330DH5kk8NgibIR3cNQQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**0x00 前言**  
  
****  
**免责声明：继续阅读文章视为您已同意[****NOVASEC免责声明****].**  
  
  
开始增加一些优质工具和项目的分享，增加公众号文章总数。  
##   
  
# afrog：高性能Web漏洞扫描器  
  
在漏洞挖掘、渗透测试和红队行动中，afrog 是一款备受推崇的国产开源安全工具。它以高性能、低误报、强扩展性著称，支持自定义 PoC，内置丰富的漏洞检测能力，助力安全从业者高效发现和验证各类安全隐患。  
  
## 主要功能亮点  
- **高性能与稳定性**  
：afrog 采用 Go 语言开发，扫描速度快、稳定性高，适合大规模目标批量检测。  
  
- **丰富的内置 PoC**  
：涵盖 CVE、CNVD、默认口令、信息泄露、指纹识别、未授权访问、任意文件读取、命令执行等多种类型。  
  
- **自定义 PoC 支持**  
：用户可灵活扩展自定义 PoC，满足个性化检测需求，社区活跃、更新及时。  
  
- **详细报告输出**  
：自动生成详细的 HTML 漏洞报告，支持 JSON/JSON-All 格式，便于集成与复盘。  
  
- **多目标批量扫描**  
：支持 URL 文件批量导入，适合资产测绘与大范围安全巡检。  
  
- **多维度筛选扫描**  
：可按关键字、漏洞等级（info/low/medium/high/critical）筛选扫描目标，精准定位高危风险。  
  
- **Web 管理界面**  
：内置 Web 服务，支持通过浏览器访问扫描结果，便于团队协作与结果管理。  
  
- **反连平台集成**  
：支持 ceye、dnslog、alphalog、xray、revsuit 等多种反连平台，便于命令执行类漏洞验证。  
  
## 快速上手  
1. **下载安装**  
  
1. 直接在   
Releases  
 下载最新版本。  
  
1. 或通过 Go 安装：  

```
go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
```

  
1. **常用命令示例**  
  
1. 单目标扫描：  

```
afrog -t https://example.com
```

  
1. 批量目标扫描：  

```
afrog -T urls.txt
```

  
1. 指定 PoC 目录：  

```
afrog -t https://example.com -P mypocs/
```

  
1. 按关键字或等级筛选：  

```
afrog -t https://example.com -s weblogic,jboss
afrog -t https://example.com -S high,critical
```

  
1. 启用 Web 管理界面：  

```
afrog -web
# 浏览器访问 http://x.x.x.x:16868 查看结果
```

  
1. JSON 报告输出：  

```
afrog -t https://example.com -json result.json
afrog -t https://example.com -json-all result.json
```

  
1. **反连平台配置**  
  
1. 支持多种反连平台，详见 afrog-config.yaml 配置说明。  
  
## 适用场景  
- 红队渗透测试与漏洞挖掘  
  
- 资产测绘与批量安全巡检  
  
- 自动化漏洞验证与报告生成  
  
- 安全团队日常工具链集成  
  
## 推荐理由  
  
afrog 以高性能、低误报、强扩展性著称，是安全从业者、红队、渗透测试人员的必备利器。项目社区活跃，持续更新，支持多种实用功能，极大提升了漏洞检测与验证的效率。强烈推荐关注与体验！  
  
项目地址：  
https://github.com/zan8in/afrog  
  
  
  
详细用法与进阶技巧请参考项目 README 或官方文档。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZD7m4f7uBkNfCG8BjypNEukTBkZDVyuJ2K8UM07dDyQxKM0XEyUgJ0pgl3BlrFLntreOnoe3uTwaw/640?wx_fmt=jpeg "")  
  
  
NOVASEC  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZD7m4f7uBkNfCG8BjypNEukN0Ht6Ha0XsryrmS5PAmaVeyzb3JzsH5ibx6DmpHq9e8agwMkccrwNSQ/640?wx_fmt=jpeg "")  
  
  
WINEZER0  
  
  
  
  
