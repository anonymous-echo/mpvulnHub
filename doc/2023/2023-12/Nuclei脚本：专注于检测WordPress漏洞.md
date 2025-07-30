#  Nuclei脚本：专注于检测WordPress漏洞   
网络安全交流圈  青澜安全团队   2023-12-17 11:10  
  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG6hZ8yS7hAsM0jQMliaA7rnIr7r2ib9ictTWnt2XSsB6ZgKWh9ofKvlS1dW3FPEf8tJc5jUsqxxbcgUg/640?wx_fmt=png&from=appmsg "")  
  
  
该项目供应丰富、全新的 Nuclei 模板集，专为检测 WordPress 的漏洞设计。这些模板都基于 Wordfence.com 的漏洞报告，构成了对任何需要扫描 WordPress 网站漏洞的人的重要资源。这些易于使用的模板不仅保持最新，还是开源的，允许您自行修改以适应特定需求。如果您承担着 WordPress 网站的安全责任，我们强烈推荐您利用此项目进行漏洞扫描。  
## 特征  
- 这些模板易于使用，只需一个命令即可运行。  
  
- 这些模板基于 Wordfence.com 的漏洞报告。  
  
- 这些模板会定期更新，以确保它们始终与最新的漏洞保持同步。  
  
- 这些模板是开源的，因此您可以修改它们以满足您的特定需求。  
  
- 可以标记手动增强的模板以避免覆盖它们。  
  
  
### What's in it?!  
  
<table><thead><tr><th><span style="display: inline !important;">类别</span></th><th><span style="display: inline !important;">总</span></th></tr></thead><tbody><tr><td><span style="display: inline !important;">WP插件</span></td><td transmart="">9494</td></tr><tr><td>wp-themes</td><td transmart="">282</td></tr><tr><td><span style="display: inline !important;">WP核心</span></td><td transmart="">329</td></tr><tr><td><span style="display: inline !important;">其他</span></td><td transmart="" style="word-break: break-all;">16</td></tr></tbody></table><table><thead><tr><th><span style="display: inline !important;">严重程度</span></th><th><span style="display: inline !important;">总</span></th></tr></thead><tbody><tr><td><span style="display: inline !important;">信息</span></td><td transmart="">7</td></tr><tr><td><span style="display: inline !important;">低</span></td><td transmart="">55</td></tr><tr><td><span style="display: inline !important;">介质</span></td><td transmart="">6948</td></tr><tr><td><span style="display: inline !important;">高</span></td><td transmart="">2296</td></tr><tr><td><span style="display: inline !important;">关键</span></td><td transmart="">807</td></tr></tbody></table>  
## 用法  
  
要使用模板，您需要安装 Nuclei 和  nuclei-wordfence-cve 存储 库。安装 Nuclei 后，您可以运行以下命令来扫描漏洞：  
```
nuclei -t github/topscoder/nuclei-wordfence-cve -u https://target.com
```  
## ‍‍安装  
  
安装此  nuclei-wordfence-cve 存储库中，您可以使用以下命令：  
```
export GITHUB_TEMPLATE_REPO=topscoder/nuclei-wordfence-cve
nuclei -update-templates
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG6hZ8yS7hAsM0jQMliaA7rnIdwIbrqT4wkTJZICELhBibBGJXjrwlZSBolwX7JP3NmpZtATiaqAD8Jdw/640?wx_fmt=png&from=appmsg "")  
  
下载地址：https://github.com/topscoder/nuclei-wordfence-cve#usage  
  
欢迎添加微信进行业务咨询：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7gqeIdG5PgEfStMv2NjgTtLFibNg95agAOlNJGerlYBIL5icrjdRQgn7kPKB9xDkk37ZHTXEiaNPPpw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
承接以下业务：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG6A6H4s2wQyk10Hg7M4kkTkTibpaia4ar7KlgSicXVFnicKPl8CWXbEKVlvManAicrjReV9aw5icJxxamFw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
```
```  
  
