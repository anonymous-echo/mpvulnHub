#  DataEase 远程代码执行漏洞分析  
 重生之成为赛博女保安   2025-06-09 09:55  
  
## 漏洞描述  
  
**DataEase**  
 是一款开源的数据可视化分析工具，旨在帮助用户快速分析数据并洞察业务趋势，从而实现业务的改进与优化。  
  
**漏洞影响版本：**  
 DataEase < 2.10.10  
  
**漏洞详情：**  
 在过滤H2 JDBC连接字符串时存在大小写绕过，攻击者可配合JWT鉴权逻辑缺陷，构造特定的JDBC连接字符串执行任意代码，造成前台远程代码执行漏洞。  
## 环境搭建  
  
下载一键安装包：  
```
```  
1. **解压并执行安装脚本**  
  
1. **修改配置文件**  
  
  
/opt/dataease2.0/docker-compose.yml  
  
![配置文件修改](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OallHDSAVcUoeI9PbWxjlgfuTUTmZnw124rJBuFqRrUdicFdU1zYAUjAw/640?wx_fmt=png&from=appmsg "")  
- JAVA_DEBUG=true  
  
- 添加端口映射   
5005:5005  
 开启调试模式  
  
**重启服务**  
```
```  
## 漏洞分析  
```
```  
  
![修复提交](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaRBAibulFn0mdwUotvO4k61XvFDq5TE1D6pep1j0BG6LZoAZuF5tRlHw/640?wx_fmt=png&from=appmsg "")  
  
从这个commit里可以发现修复了两处地方：  
### JWT鉴权逻辑缺陷  
  
**位置：**  
  
io.dataease.auth.filter.CommunityTokenFilter#doFilter  
  
![JWT鉴权缺陷1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oa3CCGWgdmU6dEBytaCWLwGtloYjb0Z6uGRjziaic8xa2gEH5mH2WN6Pfg/640?wx_fmt=png&from=appmsg "")  
  
![JWT鉴权缺陷2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oa6s7KuP5zIm3QibaF9edDZsomqqCXskeG5z4bCB779ibjKHYHoKZUg85Q/640?wx_fmt=png&from=appmsg "")  
1. **从请求头获取JWT：**  
 从   
X-DE-TOKEN  
 获取jwt进行验证  
  
1. **验证异常处理：**  
 验证异常后设置返回包但没有结束整个流程，会继续进入到   
filterChain.doFilter  
  
1. **绕过条件：**  
 如果单看这里的话实际上只要   
X-DE-TOKEN  
 不为空即可通过权限校验流程  
  
**实际测试发现的问题：**  
  
**第一个原因：**  
 获取jwt的密钥是从jwt解析的uid然后通过uid获取用户密码再md5的值，如果获取的uid值不存在的话会直接异常，不会进入下面的异常，所以还是要一个存在的uid值。  
  
**第二个原因：**  
 TokenFilter过滤器也验证了   
X-DE-TOKEN  
  
**位置：**  
  
io.dataease.auth.filter.TokenFilter#doFilter  
  
![TokenFilter1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OalT6VWRer5gsKJGl7ew0YxTLGgvTXQmMgicCchia0BwTj7zib3A3xfS1LA/640?wx_fmt=png&from=appmsg "")  
  
![TokenFilter2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oax0vp2DKheuBTAzPp3pqzHnA0BFBoUBD26Tvjf4weG4nvzhicicsEM11g/640?wx_fmt=png&from=appmsg "")  
  
![TokenFilter3](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaXItFM8n0Yt6gonIsukDp3CQuEAHF6p2ZibL7mAbAs75zyj2ML9rATgA/640?wx_fmt=png&from=appmsg "")  
- 仅验证了   
X-DE-TOKEN  
 长度大于100  
  
- uid值不为空  
  
- **没有进行密钥验证**  
  
**综合上述分析需要满足下列条件：**  
- uid值需要为存在的值  
  
- X-DE-TOKEN  
 长度大于100  
  
- oid不需要都可以  
  
**官方安全公告：**  
```
```  
  
官方公告这里是填了oid的，其实可以不需要oid，随便写什么让生成的jwt长度大于100即可  
### H2 JDBC RCE大小写绕过分析  
  
**位置：**  
  
io.dataease.datasource.type.H2#getJdbc  
  
**触发点：**  
- /de2api/datasource/validate  
  
- /de2api/datasource/getSchema  
 （POC一模一样）  
  
直接登录后台即可发现这个功能点  
  
![触发点1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oaz8iaVP6E1Jvdtq13pkfChXNMsiaiba9BC0CO7Zul2YpS6krY3lcyTzMxA/640?wx_fmt=png&from=appmsg "")  
  
![触发点2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaW2SoFE5t24EPFnyfZz8ZYI9saOBm74hqOGGLBWxUsU8emSlPKzC5jQ/640?wx_fmt=png&from=appmsg "")  
  
不需要审计黑盒都可以测试出来，点击这两个功能即可构造出数据包。  
  
![功能点1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oad6TN2fazhnG970EpibwjvIsXRty2dVV43ytDnEPAXwUDOHK1wxqFjibg/640?wx_fmt=png&from=appmsg "")  
  
![功能点2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaadMOOSonSiaxfCO7wzzacV76x7nkdo9vgibL5oZDoWZcIRpmpMjL2WUg/640?wx_fmt=png&from=appmsg "")  
  
最后会触发getJdbc方法  
  
![过滤绕过](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oa3mmA2vccKUUyibqYhUzAIXFiarL00tYKPsAv8RxSYlJPEd23yLqE4icSw/640?wx_fmt=png&from=appmsg "")  
  
**绕过方法：**  
  
将   
INIT  
 改为   
INIt  
 即可绕过过滤  
## 漏洞利用  
  
使用如下JDBC payload即可RCE，  
不太明白官方POC先去加载sql文件然后加载xml的原因。  
```
```  
  
![RCE测试1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9Oamib7L4Bc2dKRpsUKJ2WqWZmlkUfYkJ8fO46Ixhm6ibHkHATl0Ckk2jhA/640?wx_fmt=png&from=appmsg "")  
  
![RCE测试2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OafamPA26UH2XWuRmXmiculcKLamuFPwm17ZMB6Kd5DNs7iaQ7uMK83f7Q/640?wx_fmt=png&from=appmsg "")  
### 内存马注入  
  
最开始直接使用java-chains生成JDBCPayload发现不行，有两个原因：  
  
**1. JDK版本问题**  
  
  
DataEase2.10.9  
 JDK版本为21  
  
![JDK版本](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OafYiaQTCXpJ4toCicib3UCB5RG5flpwCBNcrNa3nE96AaSibOTBwtqDycOA/640?wx_fmt=png&from=appmsg "")  
  
**2. Tomcat版本问题**  
  
使用的tomcat版本为10  
  
![Tomcat版本](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaXcpNuj2Rr7xZxpqDHk9d0k92j0UYiaMwZdRSdum8P01URUTugbR15nw/640?wx_fmt=png&from=appmsg "")  
  
折腾了一下最后使用如下JDBCPayload即可成功打入内存马（需注意转义问题）：  
```
```  
  
**tomcatStr使用jmg生成**  
  
![jmg工具1](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OajzSvvJXdM0icbnPP6GOLibRAEIFe2Cl9YlSOF7jDbUf1cTKGwzTGzFKw/640?wx_fmt=png&from=appmsg "")  
  
![jmg工具2](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaV7oEicpugokPEOWWFHJttcdo96UEH7pSpvkyIOPBXH382bRWMv5PNbQ/640?wx_fmt=png&from=appmsg "")  
  
![jmg工具3](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHW9QZI5Xxe2XhGRC7qwW9OaxVia7r5cYIe4xMIDh7sYicic9biao5ld6RkR7EBdZWpJ2UW46OjeGQlusA/640?wx_fmt=png&from=appmsg "")  
## 漏洞补丁  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHVLSbibcAT49aw4pkibVq3bJWqJanXicdo5ibqp8HBHpstKvnhOxwLnAZo0TiajicibXfv44qXFvh1AFxJBQ/640?wx_fmt=png&from=appmsg "")  
  
jwt鉴权这里进入异常以后直接return，不会再进入后面的流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHVLSbibcAT49aw4pkibVq3bJWfxthPYJYic0tkCAQUjCtlPMhmTCQItKhVVxstabLHB51nYS0CL2Iibcg/640?wx_fmt=png&from=appmsg "")  
  
JDBC连接字符串全部转为大写以后再匹配(幸亏没弄成小写不然又有问题  
🐶  
)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/AKz6F8hGbHVLSbibcAT49aw4pkibVq3bJWDatmEFziahZ0iaN6GYjXLibXhjEaiakadFw3HoQh22tM8wl2rl7lzlPYMA/640?wx_fmt=png&from=appmsg "")  
  
  
实际上这个JDBC的地方还是可以绕过留给读者思考吧。  
  
本文仅供安全研究和学习使用，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用本人负责，公众号及文章作者不为此承担任何责任。  
  
