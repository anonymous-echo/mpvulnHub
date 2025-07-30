#  漏洞挖掘—隐藏资产挖掘SQL注入   
原创 haosha  网安日记本   2025-05-03 11:00  
  
**免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。**  
  
**前言**  
  
    最近看各位大佬都在冲EDU SRC看的我是热血沸腾，搞得我也想试一试，于是便趁着工作之余挖掘了一些学校的漏洞，也是成功攒下了一波素材，如果漏洞修复比较快的话，后面周更应该是没什么太大问题了。  
  
**一、发现隐藏资产**  
  
**本来看到这个学校的我是真的不抱希望，学校的资产太少了，我是直接C段资产挨个点了一遍，而且网上公开的信息也是少的可怜。**  
  
**没办法了，只能上搜索语法进行信息收集，看看能不能有什么意外惊喜。这不，在使用谷歌搜索语句时，确实有了意外发现。使用 “site:XXX.edu.cn 注册” 语句进行搜索时，还真发现了一个可以注册的界面，点击进去查看是一个就业管理系统，公司可以进行注册，发布招聘信息。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAnGJS7Fa4vTpGljsfiaPND6SkQEQWSsGYuwwjBBibENS6bcfSE5XuwYoA/640?wx_fmt=png&from=appmsg "")  
  
    而且这个站点是和学校统一认证是同一个域名，只不过使用的是一个单独的目录   
“/JiuYe”   
，后面通过对学校统一认证页面源码查看也是发现，这个注册界面的地址竟然就写在源码里面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDARZibWE1QNjWftAVuicgm3Qxia8Q9ib1DBaAicu6mDJngutpLH5Btuy3faqA/640?wx_fmt=png&from=appmsg "")  
  
**二、储存型XSS**  
  
    利用注册页面进行注册，注册时需要填入统一社会信用代码和公司名称，这里面我直接使用工具生成了一个公司名称是我乱编的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAMZQoDibDguQC9KBfuxXUW9fMrAabVOwVBfcsTiaIGiaTTfRcKibNtT8VwA/640?wx_fmt=png&from=appmsg "")  
  
    成功注册登录之后，发现功能点也很少，但是好在站点比较老旧，感觉很容易出洞。在点击 “招聘会企业报名” 中发现可以发布招聘信息，尝试在招聘信息中插入XSS语句。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAAIPuQTyoVXYD2mia8WQx8JrKM9QKNicRBwibQnIHlOKjyichNkKr8UOKUQ/640?wx_fmt=png&from=appmsg "")  
  
    成功添加后重新点击“招聘会信息”成功触发XSS，可获取用户cookie。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDABeAOMa0HdARiakH48yVBIdZsU46G3jXDV9bnPNujQbDOiafT7N6cW7bA/640?wx_fmt=png&from=appmsg "")  
  
    因为是企业发布招聘信息，所以学生是能看到的，这里我更改了一下XSS语句，配置XSS接收平台，可以利用漏洞进行钓鱼攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAkNqarkcZUqW6MxLewSVTq3qywXuyygJuVuIQltushMtelNkFqQO85g/640?wx_fmt=png&from=appmsg "")  
  
**三、SQL注入**  
  
    到这里就已经出洞了，但储存型XSS在EDU SRC里面只能算是一个低危，只有1rank，肯定不能到此为止啊。继续查看功能点，在 “我的招聘会信息” 中发现了一个查询的功能点，企业名称输入任意值，发送数据包利用burp进行抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAUUa1tvlVg2avtLU1wjGEp4FjK7suiaYeIv6V2dXjoGL7F127FAdbXCQ/640?wx_fmt=png&from=appmsg "")  
  
    流量包大概是下面这个样子的（关键信息已删除或者替换），使用了POST传参，其中有一个参数名为 “orderbyName” 而且参数为 “desc”，这很难不让联想到这里会不会存在SQL注入漏洞，于是对参数进行闭合发现成功报错，回显报错信息判断为Oracle数据库。  
```
POST /JiuYe/XXX/XXX/myjiuye.jsp HTTP/1.1
Host: xxx.xxx.edu.cn
Cookie: JSESSIONID=89D3336C7289863A296EDFBA59839AB7-n1.tomcat1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
Connection: close

orderbyName=desc
```  
  
    确实不太清楚Oracle数据库的SQL语句，直接保存请求包修改一下，只保留orderbyName参数，利用sqlmap工具进行测试。  
```
sqlmap -r sql.txt --batch -p "orderbyName" --dbms=oracle
```  
  
    成功爆出当前用户名和当前数据库名，证明存在SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDAsA1BaD52zEzbnoV2bPDfnq6RKgzq3B6zydm6NNoE7ebXA8NicDiamXeQ/640?wx_fmt=png&from=appmsg "")  
  
结尾  
  
    依旧是全靠信息收集，没有任何手法，拿下一个高危漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529c9ROibicsgkE4dW5LFxAnaWDA3V274clmY2Nv5Yia3I0EFkibImBr0AGn2VldUJicfXic3GqA7M1eVmYYBw/640?wx_fmt=png&from=appmsg "")  
  
