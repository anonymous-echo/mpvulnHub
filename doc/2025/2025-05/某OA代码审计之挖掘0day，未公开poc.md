#  某OA代码审计之挖掘0day，未公开poc   
 黑白之道   2025-05-17 09:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
参与的众测项目，资产非常难挖掘漏洞，所以只能通过审计的方式，找找漏洞点  
  
资产里相对用的多的 oa，都是用友，泛微，致远等大型 oa，对我这种小菜来说，直接上手有点难度，无意间发现了金和系统，就直接来审计学学，刚开始找网盘资料，发现有个 net 版的源码，结果目标系统是 jsp，就 G 了。  
  
然后就找朋友要了安装包，对源码进行分析，跟踪路由，审计漏洞点。  
  
但是有一点就是sbcp是真他妈恶心，水平越权，只因 id 不易猜测，直接驳回，任意密码重置，通过 id，可直接重置密码，不需要验证，也是因为 id 不易猜测。真他妈气打不一出来  
  
你他马勒戈壁，回答我，你的安全是谁教的，这他妈不是漏洞吗，look in my eyes  
  
                                ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw7Igiay2ianjQSSKxvamVibNicM1f6q2VhLC9NqeX9GCPv0fFUfxiarpKxYA/640?wx_fmt=png&wxfrom=13&tp=wxpic "")  
  
  
  
路由关系寻找  
  
开始正题，第一次审计，所以不太了解路由关系，大致看了看代码结构，发现相对简单点。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awvuxeekRogprYYaEIev3YJWn4BpeqRXOgsfQSlEiaibnMF2jMVpaIMRwA/640?wx_fmt=png&wxfrom=13&tp=wxpic "")  
  
  
整体文件那么多，主要是关注 WEB-INF/jsp 文件夹，这是对应的视图文件，也就是访问 web 页面的 jsp 文件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awg8vzOcUt8K7KP7awSibX1zp7M3GwHtflPh8Pj1a85XFX8Uia30LdxUVg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
我并没有分析那些需要鉴权，那些不需要鉴权。  
  
这个网上有个模板注入漏洞，我是根据对应的二级目录来找的相关漏洞点，后面也是发现了注入，但是是Hibernate，构造半天没读出来数据库名  
  
jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action  
  
然后就是根据portalwb目录下的文件去挖掘注入。  
  
然后再其次就是关注后台文件，也就是 lib 下的 jcs-xx.jar文件，这才是后端代码。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awCISk45HV4abSOQj6eGkiaNV0HFuqPEzicHYVawOcDCLicicLYyCZibtQ0fA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
根据上面的路径  
  
jc6/platform/portalwb/portalwb-con-template  
  
就可以知道，对应的 jar 就是 jcs-platform-java-xxxxxx.jar。  
  
  
HQL注入  
  
经过我不懈的努力，在 jsp 页面中，找到了一个参数  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awMbvcqicRIOYB0V5yJd4QUhzMUch9CN9KMk9Wialj93dwmcktVPAibot1A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
那如何在后段代码，找到对应方法呢  
  
很简单，例如：  
  
main.action!viewConTemplate.action==main.action?方法名=viewConTemplate  
  
portalweb-datasource.jsp则是前端的文件，后端也会存在对应的路由，然后方法名则是下面的，getTemplateOpt  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awLpSNaibWkNIk02OdfLHAfIKWVKID8S5n05X92gUMOHV6icRWuTn0Q7vw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw1rra74SB83liapqpnUUSHRXfEdmJVQy5ho3VsSzEzxgR2fU2TpSAQ8Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这里有typeFlag参数，我们跟踪getAllTemplates方法  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw6tT573bGrTibSz9tBCx7VPq6sGYElbdoF6PLQ5qCpDxPSGfY9RDddeg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
直接对应了接口名称，往下跟，就到了数据库层面了  
```
   @Override
   public List<TblPortalwbConTemplete> getAllTemplates(String typeFlag) {
      String hql = " from TblPortalwbConTemplete  t where   t.commRecordIdenty= '1' and t.typeFlag like '%" + typeFlag + "%'";
      return this.find(hql);
   }


```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awClVkJGh4QC8Go6xkrYbK3EbQPLf1dFJl5euNmm40tWAyzwnd98EsAg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
直接是拼接的 sql 语句  
  
于是就可以构造请求方法了  
  
jc6/platform/portalwb/dataSource/portalwb-data-source!getTemplateOpt.action?moduId=1&typeFlag=1  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awpUNWuDbM0RktibNwWibB2PycSWJ4S4goCJzHhb9UGWG9uicOxpfb0flZQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awVMzxTETvJDRA6hQkcjAm0JC0eRkl84XS1zfkB1lrLN8JYmibbrUuIqQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw8URoAMCItKpaUwed6M9qLJibiar0sPN87iaDkr12RuQLlKkFUVbGtBDzA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
仅限于 or 1=1 也尝试构造数据包读取数据库  
  
  
SQL 注入  
  
于是放弃对业务数据的审计，翻了翻下面的 jar 包  
  
jcs-eform-java-1.5.0-SNAPSHOT.jar  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw4qxdcTnhHsEYGVdXkib6A7s2fPhKfEZgBU82JNq6yRic5SAgXpZf4j2g/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
clobfield这个接口，网上有，也是我审计之后发现的，不过目标系统存在这个接口，注入点变成了sKeyname  
  
通过req获取请求参数，参数跟进  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awVFD7XA3pdY9oxsbmdNhBgAlSBY1otFx7nXiaicMkXLEZn3R2ibjRlv65w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
clobfield1 存在查询语句  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awLTvCQSxolJoIDw14Qze5DZWQZD53KUTJaem5Yv9BISQk2bSxfuCVgg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
直接拼接，无过滤  
  
构造访问参数，需要满足key包含readClob  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5aw4tx0LoDTXp5TT0rCOo07y0QI6hufw6Gl0bde9ExNFq1xJDK3CnRJRg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
```
POST /jc6/servlet/clobfield HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 91

key=readClob&sImgname=1&sTablename=1&sKeyvalue=1&sKeyname=1
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awsuApNEW0tfkZemATNTJBPk4xjkxnmb6GNBXlmmaLZxmeHR4WXlHBCw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
XXE 漏洞  
  
想着，这几个servlet 有两三个接口都存在漏洞，那么剩下的是不是也存在。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awicvGwvp3FWFBXc9GJtNUlxuF3cAzjkmxhvcXjkBX9PdxQ9VDooUyc2w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
post方式，创建SAXReader，用来读取xml信息，全程代码就那么多，可见未过滤任何信息  
  
路由访问,因为继承HttpServlet，所以直接拼接访问  
  
dnslog 尝试  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awKoPfXtbDem6pXAuw0UNSmYsjsZLBDcJWkiadXG2foU9uaticpvL3YAYA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awwaDR6C1qO5t3cHWZI8pr5JPLiajHydSq13W7sDHUVOCHmhHygibK83TA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
然后就是读取windows/win.ini  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awU16XWU3FqhKdGtf94AN8rfbGcq2lGpqrgZkq4D8L1qbNXtZe3hqiaBw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
我感觉那么简单的漏洞，应该是被提交了  
  
果不其然  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQaHNMcUhPPqY7T6OdSeg5awcOPbvYLmfbLRpJpPRMHnjFR5LZrtxqWfiad0bnxsTolWqNVJEZLQ9Sg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
