#  统计路由器CVE，便于漏洞挖掘   
 黑白之道   2024-01-20 09:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**01**  
  
**工具介绍**  
  
统计路由器CVE，便于漏洞挖掘  
  
使用：  
```
python checker.py
```  
  
在checker.py  
中指定要统计的路由器  
```
if __name__ == "__main__":
    banner()
    keywords = ["tenda","tp-link","mercury"]
    for word in keywords:
        cve_list = get_cve_json(word,1)
        result = {}
        page = 2
        while(stastic(result, cve_list)):
            # info(word, page)
            cve_list = get_cve_json(word,page)
            page+=1
        with open(word+".log","w") as f:
            f.write(str(result))
            f.write("\n")
        info("="*0x10," "*5,word," "*5,"="*0x10)
        for i in result:
            success(i.ljust(35," "), result[i])
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5Fh06DTn0bmseluklC26J4FmdXlibGqbviciaAuGBPfdzMiayv0AAet2Bqfuw/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
  
**02**  
  
**工具下载**  
  
****https://github.com/Joe1sn/route_fileter****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
