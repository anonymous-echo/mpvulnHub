#  金融业“隐藏content-type”漏洞   
原创 testbywlp  安全边角料   2025-03-23 23:11  
  
       
我们都知道，在http(s)协议中，content-type经常会被用来告知服务端应该怎么去参数化处理这个请求Body，不同的处理方式可能有不同的漏洞。就目前而言，金融业大多数使用的是json格式传参数body,但这并不意味着服务端只能处理json格式的数据，因为一个接口可能被多个端请求，比如后端服务端或者pos机传递的时候通常会使用xml格式。  
- 前言  
  
      
最近的一个金融业测试项目，发现参数是json格式的，因为之前看过类似的测试思路就想着死马当活马医，然后直接使用Burpsuite插件将json修改为xml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiatwQ39L2YiczKuPPOBcWeaaRXhpFWHAB4NNiaSZkvUBzSGUyweMndet5eQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiataa2ApvZXsg6fddnkSDIepibnVg1iaZD8xKAMmwqp81opicP4B8cTlQXibw/640?wx_fmt=png&from=appmsg "")  
  
      
上面这种转换会导致服务端报错xml参数化失败，然后又通过大模型转化成如下结构，服务端成功处理这个请求并返回正常的数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiatugPHAibIBDibEaqZ33w13L9XGhs6iaA10V9AZjt0TF9UgCxbR1snRCyPw/640?wx_fmt=jpeg&from=appmsg "")  
- 漏洞利用  
  
      
既然支持xml，那么我们常见的几种测试方法就可以上场了。首先是xxe漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiatmbibTxG4iaRxsjFVfanOpVfic0oC1fvEOM8tV3QMDMLdicLsA1YEeas72Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    金融业的waf其实挺好绕过的，直接绕过成功捕获一个xxe漏洞，高危到手。如果文件读取没法做到可以试试别的，如dos(  
当然提前和客户沟通好)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiatDhVyJOAqcdRa4SPKBU6cNLqibDJsiaaqG4tNw9l5ouK8tfSoicwLUwvLA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiatGXKXzIalWiaBSzs95P3Q0Is9GiaibdBoGy9Pvenzx14A7RHgxj7ib9623Q/640?wx_fmt=png&from=appmsg "")  
- 自动化  
  
      
目前没找到很好的工具，只能通过现有的burpsuite插件，所以需要把常见的xml库报错集成到hae中命中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1W2WgV9zs259O3E9ibOKxjiat9UULicomY0yYIKP19KfJcbvN5KgPuF1jGebicLmruPyPRpwibTCPgOkbA/640?wx_fmt=jpeg&from=appmsg "")  
- 参考文章  
  
1.  
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#xxe-on-json-endpoints  
  
2.https://chetan-conikee.medium.com/detecting-chained-xxe-xml-external-entity-to-dos-denial-of-service-or-ssrf-server-side-d13df22001c7  
  
3.  
https://www.netspi.com/blog/technical-blog/web-application-pentesting/playing-content-type-xxe-json-endpoints/  
  
