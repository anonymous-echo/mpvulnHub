#  nginxWebui后台任意文件读取漏洞&rce分析-0day&nday   
原创 深潜sec安全团队  深潜sec安全团队   2025-04-25 00:10  
  
## 免责声明  
  
免责声明：文中所有涉及的内容均不针对任何厂商或个人，同时由于传播、利用文中所发布的技术或工具造成的任何直接或者间接的后果及损失，均由使用者本人承担。  
  
关注公众号，输入“学习交流”加入交流群  
  
觉得不错的话，可以多点赞、分享、关注  
## 介绍  
  
任意文件读取漏洞网上没有详情，暂且可以归于0day，为了避免麻烦，需要该漏洞添加群聊免费获取，RCE是一个历史漏洞这里进行分析的。  
## 一、任意文件读取审计过程  
  
1.  
通过全局搜索FileUtil相关参数，发现漏洞代码处  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6scia6VXypmrQS0kWeFND9c1A4GjbuicelfLu4yPKlicdcGfJcq0DicV3djseg/640?wx_fmt=png&from=appmsg "null")  
  
2.  
发现代码是直接通过nginxPath参数读取文件，代码中没有发现过滤器或白名单存在，但是构造对应的数据包时发现需要权限鉴定，于是回头查看鉴权部分  
```
public JsonResult loadOrg(String nginxPath) {
     String decompose = this.settingService.get("decompose");
     ConfExt confExt = this.confService.buildConf(Boolean.valueOf((StrUtil.isNotEmpty(decompose) && decompose.equals("true"))), Boolean.valueOf(false));

     if (StrUtil.isNotEmpty(nginxPath) && FileUtil.exist(nginxPath) && FileUtil.isFile(nginxPath)) {
       String orgStr = FileUtil.readString(nginxPath, StandardCharsets.UTF_8);
       confExt.setConf(orgStr);

       for (ConfFile confFile : confExt.getFileList()) {
         confFile.setConf("");

         String filePath = (new File(nginxPath)).getParent() + "/conf.d/" + confFile.getName();
         if (FileUtil.exist(filePath)) {
           confFile.setConf(FileUtil.readString(filePath, StandardCharsets.UTF_8));
         }
       } 

       return renderSuccess(confExt);
     } 
     if (FileUtil.isDirectory(nginxPath)) {
       return renderError(this.m.get("confStr.error2"));
     }

     return renderError(this.m.get("confStr.notExist"));
   }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciaLUjIO9PhJANyxnZB2dTiazMpvjAsjAH87MzB096gyE6qNuwwT7Ek1fQ/640?wx_fmt=png&from=appmsg "null")  
  
跟踪getAdmin()来到BaseController代码中，发现代码逻辑如下  
```
public Admin getAdmin() {
     // 1. 从session获取admin对象
     Admin admin = (Admin)Context.current().session("admin");
     if (admin == null) {
       // 2. 从header中的token获取
       String token = Context.current().header("token");
       admin = this.adminService.getByToken(token);
     } 
     if (admin == null) {
       // 3. 从参数creditKey获取
       String creditKey = Context.current().param("creditKey");
       admin = this.adminService.getByCreditKey(creditKey);
     } 

     return admin;
   }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciagt04aT46s0iaGM7BTohBvT9SMBRl7JPu8oMe1wquB4Oe50e1AXAa6kQ/640?wx_fmt=png&from=appmsg "null")  
  
3.  
构造数据包如下(需要登录进去，没有尝试低权限账户能否读取)![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciam9haOibb3k014AibfCTjEm4nw9aibrvGJEhL3Ca3YcdOALEQ42nZ66MLA/640?wx_fmt=png&from=appmsg "null")  
  
## 二、nginxWebui-RCE nday分析  
  
1.  
审计这个系统之前我搜索了该系统之前暴露出来的漏洞，发现后台还存在命令执行漏洞，如是就分析了一下怎么修复的，代码如下  
```
public JsonResult runCmd(String cmd, String type) {
     if (StrUtil.isNotEmpty(type)) {
       this.settingService.set(type, cmd);
     }

     //这段代码应该是新加的规则或检测
     cmd = buildRealCmd(cmd);
     if (StrUtil.isEmpty(cmd)) {
       return renderSuccess(this.m.get("confStr.notAvailableCmd"));
     }

     try {
       String rs = "";
       if (SystemTool.isWindows().booleanValue()) {
         RuntimeUtil.exec(new String[] { "cmd /c start " + cmd });
       } else {
         rs = RuntimeUtil.execForStr(new String[] { "/bin/sh", "-c", cmd });
       } 

       cmd = "<span class='blue'>" + cmd + "</span>";
       if (StrUtil.isEmpty(rs) || rs.contains("已终止进程") || rs
         .contains("signal process started") || rs
         .toLowerCase().contains("terminated process") || rs
         .toLowerCase().contains("starting") || rs
         .toLowerCase().contains("stopping")) {
         return renderSuccess(cmd + "<br>" + this.m.get("confStr.runSuccess") + "<br>" + rs.replace("\n", "<br>"));
       }
       return renderSuccess(cmd + "<br>" + this.m.get("confStr.runFail") + "<br>" + rs.replace("\n", "<br>"));
     }
     catch (Exception e) {
       this.logger.error(e.getMessage(), e);
       return renderSuccess(this.m.get("confStr.runFail") + "<br>" + e.getMessage().replace("\n", "<br>"));
     } 
   }

   //这个是过滤器或者白名单
   private String buildRealCmd(String cmd) {
     String dir = "";
     if (StrUtil.isNotEmpty(this.settingService.get("nginxDir"))) {
       dir = " -p " + this.settingService.get("nginxDir");
     }

     switch (cmd) {
       case "net start nginx":
       case "service nginx start":
       case "systemctl start nginx":
       case "net stop nginx":
       case "service nginx stop":
       case "systemctl stop nginx":
       case "taskkill /f /im nginx.exe":
       case "pkill nginx":
         return cmd;

       case "stopNormal":
         return this.settingService.get("nginxExe") + " -s stop" + dir;
       case "startNormal":
         return this.settingService.get("nginxExe") + " -c " + this.settingService.get("nginxPath") + dir;
     } 

     return null;
   }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciagXOx26DDGnaHUNh5iavekK6wAr00lTRt3ZwXEhZLtEh9yrsPfUz5dgA/640?wx_fmt=png&from=appmsg "null")  
  
2.  
跟踪代码发现新加了一个buildRealCmd白名单，只允许执行下面给出的命令，其他命令无法执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciaGPicwy25dYnOabicBP7Ml7RnNgckexPpibESZKnlFfqRz0o6cupFPTTibQ/640?wx_fmt=png&from=appmsg "null")  
  
3.  
如果你执行命令不在上面的列表中，就走renderSuccess(this.m.get("confStr.notAvailableCmd"))中的提示"不被允许的命令"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6scianb1bpiciaI6demZTpgeklAsWBV2Xh9rT67LE1WJeTudV61g8ptbEdicaA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciaro4F4H3y7ic5TnJRmlJU4CT6PPVnicE4LjP0sFKAJMBNGThzPCZuk5Jw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciawrv0skgHviahNNXAhIyYibxXx7ibzhWwTj7IRgVtTlQkRSbPVfc1ibn1Ug/640?wx_fmt=png&from=appmsg "null")  
  
执行上面白名单中的命令就可以正常运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdw8ibUHxpcwmfnjxaNTz6sciaDl39uCGMAyW3zhhTtWEDW877dL1yoDKFHoMoHXOILUjMicIp2XIIicqg/640?wx_fmt=png&from=appmsg "null")  
## 三、总结  
  
主要是因为我接触代码审计还不太熟练。不过，通过这次审计，我对代码有了更深的了解，也收获了不少新的知识和思路。希望各位前辈能够指出我在审计过程中可能存在的错误，或者提供一些新的思路和建议。  
  
  
