#  oss存储桶遍历漏洞利用工具   
 黑白之道   2024-11-26 01:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
**01**  
  
**工具介绍**  
  
存储桶遍历漏洞利用脚本批量提取未授权的存储桶OSS的文件路径、大小、后缀名称提取的结果会自动生成到csv和xlsx文件中  
  
安装：  
```
pip3 install pandas
```  
  
使用：  
```
python3 ossFileList.py -u https://xxx.oss-cn-xxx.aliyuncs.com/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvStttMyUEPibXC3ibcqWiaX5Q3ic8ic9Ozav6Yw7NMublkY6TLXC4aDXRfh0xnw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
优化：1.自动生成的csv文件后，通过filetype拆分成不同的工作表，易读。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvSttxjBibESCXhUaA69Ppf1BEiaaBRABSgo6TorMnaIOp3iaQeQHO65jtagLQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvSttXoMHjYP7I8DTB1p82HPuV5PTDACD78KQYibXOq3B0vbmhCG9SPiblMnw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2.修复XML解析有误，无法遍历的bug  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvSttypVo9cBDSdGTk4NcUnibfBlC0eLokQfcQAxp4RjVpmvpPae0U4M162A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
TODO:下个版本增加url批量   
```
python3 ossFileList.py -f filename
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvSttywfj6RUMz2X0JApUiav6OEqO1FtH2RqUVbPLHrKTFRVYSsHiajw6icmNA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpBpmYhRkicghKQSynkvStticw69B0Ox5dl7Rnx4iaU2Xqc0HRORhdp6XpFRT0Yl8HXRarsfHrxY0ibw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
```
原作者：https://github.com/source-xu/ossx
```  
  
  
**02**  
  
**工具下载**  
  
****https://github.com/d1sbb/ossFileList****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
