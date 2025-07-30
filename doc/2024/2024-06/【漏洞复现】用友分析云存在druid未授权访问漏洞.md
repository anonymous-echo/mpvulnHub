#  【漏洞复现】用友分析云存在druid未授权访问漏洞   
仲瑿  新势界NewFrontier   2024-06-14 14:00  
  
声明  
  
该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
  
公众号现在只对常读和星标的公众号才展示大图推送，建议把公众号设为星标，否则可能就看不到啦！感谢各位师傅。  
  
### 资产收集  
```
app="用友分析云"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j914cicY07Nm75FA3NsAOwtbm1uVic6vTRABIUbZlOeu7vD87XNjMtdnZzCCKDY1q7FxJhl1lR3aUM8fQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j914cicY07Nm75FA3NsAOwtbm1qC7CtuKPdm0OMibicmErjb3xpM0rXkReYK8OHr0W0icX5Y0lpAAIMA5lQ/640?wx_fmt=png&from=appmsg "")  
  
构建url  
```
/console/druid/index.html
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j914cicY07Nm75FA3NsAOwtbm1DOwgib80XLsD58yaqhiaYBYaRdH6DIficnWGL60Y6MhcKlNbAOKLDSfSA/640?wx_fmt=png&from=appmsg "")  
  
批量验证脚本  
  
关注公众号  
并回复   
“ZH-2024-06-13-001  
”  
 即可获得该漏洞nuclei脚本  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j916a1ialib97vIiaz85sHVDyr7FibbUZOzqIj49PN8XIQCbUd49fWibOoEicwaOwrfYbibTiaZta5SqribcJvjg/640?wx_fmt=png&from=appmsg "")  
  
  
