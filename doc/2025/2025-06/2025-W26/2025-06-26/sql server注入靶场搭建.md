> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU3Mjk2NDU2Nw==&mid=2247493947&idx=1&sn=885ee489f74211ba26a4a097f7ba30d6

#  sql server注入靶场搭建  
湘南第一深情  湘安无事   2025-06-26 14:19  
  
**声明：**  
**由于传播、利用本公众号湘安无事所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。如有侵权烦请告知，我们会立即删除并致歉。谢谢！**  
  
## SQL Server数据库  
  
测  
试连接数据库是否成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qakDTVoxGJdk83jnPPNBN6gEq6E93ECic6gibbHLwHw1ysVHZz7KDpetDA/640?wx_fmt=png "")  
## SQL Server的PHP扩展  
  
由于这边使用的是小皮面板，PHP版本为7.3.4nts版本  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaBianZhF5RQcGVLEvFicIR4IGEHwZnJ0Eovz33EwtRyVSIVHjM4txUxdw/640?wx_fmt=png "")  
  
下载Windwos7.3扩展文件（这里的版本号一定  
要对得上  
）  
  

```
https://objects.githubusercontent.com/github-production-release-asset-2e65be/19043988/23d51580-6213-11eb-897e-e3aa6e1ac680?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250625%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250625T072816Z&X-Amz-Expires=1800&X-Amz-Signature=2df203a2e38602acd1ae39694310ec4359023a7ac1ead47cf546592c7fbf7b22&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DWindows-7.3.zip&response-content-type=application%2Foctet-stream  
```

####   
  
  
下载成功后把这两个文件拉到该目录下：C:\phpstudy_pro\Extensions\php\php7.3.4nts\ext  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaHtuVjpapibKBPuhdPSoVVr2fqiau7ZtuLuic4eGsTdeFREu8kqGHGiazsw/640?wx_fmt=png "")  
  
对应的修改C:\phpstudy_pro\Extensions\php\php7.3.4nts目录下的php.ini文件  

```
extension=php_pdo_sqlsrv_73_nts           
extension=php_sqlsrv_73_nts          
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaDFTmy8ytKEmPlz5bDFxMkag7j3lLy2Zv1JqoepUYSrX3fGtibrkiatdA/640?wx_fmt=png "")  
  
成功添加扩展文件后重启小皮面板服务即可  
## 创建数据库数据  
##   
  

```
-- 1. 创建测试数据库
CREATE DATABASE test;
GO


-- 2. 使用测试数据库
USE test;
GO


-- 3. 创建用户表（针对字符型注入优化）
CREATE TABLE users (    
  id VARCHAR(50) PRIMARY KEY,  -- 改为字符型以支持字符型注入    
  username NVARCHAR(50) NOT NULL,    
  password NVARCHAR(100) NOT NULL,    
  email NVARCHAR(100),    
  is_admin BIT DEFAULT 0,    
  created_at DATETIME DEFAULT GETDATE()
);
GO


-- 4. 插入测试用户数据（使用字符型ID）
INSERT INTO users (id, username, password, email, is_admin) VALUES
('1', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@example.com', 1),
('2', 'user1', '5f4dcc3b5aa765d61d8327deb882cf99', 'user1@example.com', 0),
('3', 'test', '098f6bcd4621d373cade4e832627b4f6', 'test@example.com', 0),
('4', '张伟', 'e10adc3949ba59abbe56e057f20f883e', 'zhangwei@example.com', 0),
('5', '李娜', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'lina@example.com', 0);
GO
```

  
## 编写靶场PHP源码  
  
在  
WWW根目录下创建sql.php，复制以下内容进去即可  

```
<?php  
  header('Content-Type: text/html; charset=utf-8');
  
$connectionInfo = array(  
  &#34;Database&#34; => 'test',  
  &#34;UID&#34; => 'sa', 
  &#34;PWD&#34; => '123456',  
  &#34;CharacterSet&#34; => 'UTF-8'
);


$conn = sqlsrv_connect('127.0.0.1', $connectionInfo);


if ($conn === false) {  
  die(print_r(sqlsrv_errors(), true));
}


$id = isset($_REQUEST['id']) ? $_REQUEST['id'] : '';


if (!empty($id)) {  
// 字符型注入测试点  
  $sql = &#34;SELECT * FROM users WHERE id = '&#34; . $id . &#34;'&#34;;  


  $data = sqlsrv_query($conn, $sql);  


  if ($data === false) {    
    die(print_r(sqlsrv_errors(), true));  
  }  
  
  echo &#34;<h2>查询结果：</h2>&#34;;  
  echo &#34;<table border='1'><tr><th>ID</th><th>用户名</th><th>密码</th><th>邮箱</th><th>管理员</th><th>创建时间</th></tr>&#34;;  
  
  while ($row = sqlsrv_fetch_array($data, SQLSRV_FETCH_ASSOC)) {    
    echo &#34;<tr>&#34;;   
    echo &#34;<td>&#34;.$row['id'].&#34;</td>&#34;;    
    echo &#34;<td>&#34;.htmlspecialchars($row['username']).&#34;</td>&#34;;    
    echo &#34;<td>&#34;.htmlspecialchars($row['password']).&#34;</td>&#34;;    
    echo &#34;<td>&#34;.htmlspecialchars($row['email']).&#34;</td>&#34;;    
    echo &#34;<td>&#34;.($row['is_admin'] ? '是' : '否').&#34;</td>&#34;;    
    echo &#34;<td>&#34;.$row['created_at']->format('Y-m-d H:i:s').&#34;</td>&#34;;   
    echo &#34;</tr>&#34;; 
  }  
  echo &#34;</table>&#34;;
} else {  
  echo &#34;<h2>字符型SQL注入测试</h2>&#34;;  
  echo &#34;<form method='get'>&#34;;  
  echo &#34;用户ID: <input type='text' name='id'>&#34;;  
  echo &#34;<input type='submit' value='查询'>&#34;;  
  echo &#34;</form>&#34;;
  }
  
  sqlsrv_close($conn);
?>
```

  
## 测试靶场网站  
  
打开网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaNb6sciaaybeRSDXZkC1EM0IcGNpf52Z5sd0ggeMicoX3FdbFqGySI2IQ/640?wx_fmt=png&from=appmsg "")  
  
输入框输入内容：  
1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaS8CbuwSFoIKNxbe7yTxrCPybHSOFSYh31Unica4iblibgttvOj7TM16DQ/640?wx_fmt=png&from=appmsg "")  
  
id追加单引号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qa0fFBIEyYtAryv7XaTdJCxYLkuAPczHTloMRDOKeDyPDxkFBe3v7ZBA/640?wx_fmt=png&from=appmsg "")  
  
再次追加单引号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvx1rAcz09tFGA5OcS5n5qaibfj3RwnbGyMxjrFfMOeqWfoYbfpAtiboic2QIdaWoTcXJmQVmGEkxkdA/640?wx_fmt=png&from=appmsg "")  
  
靶场环境搭建结束。  
## 结尾  
  
  
感兴趣的可以公众号回答回复"深情哥**"进群，有公开课会在群里面通知，包括审计和src。edu邀请码获取也可以联系深情哥。**  
  
**内部edu+src培训，包括src挖掘，edu挖掘，小程序逆向，js逆向，app渗透，导师是挖洞过30w的奥特曼，edu上千分的带头大哥！！！联系深情哥即可。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYvzCYK6uRV3eWBuPCSd97U0l9TegsEgd3ZeG52IAcPK45TLAUFnicMDV8Rw6FCbcq5Izljmdo475WA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
####   
  
