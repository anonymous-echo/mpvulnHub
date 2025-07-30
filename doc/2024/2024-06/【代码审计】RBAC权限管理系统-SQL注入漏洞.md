#  【代码审计】RBAC权限管理系统-SQL注入漏洞   
原创 xia0chen  安全攻防屋   2024-06-16 21:54  
  
### 一、项目部署  
  
1、在IDEA中启动项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhPibHdgz18RibX76ZEfr3HsUjIPYHgyP1x3KSm1GiajzYibgLZq5ePmicwCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhovI0Hj4kNX6YDw3ia28pps1KxtbKic2O5e9jCOBickoUSia3juWx11yU0g/640?wx_fmt=png&from=appmsg "")  
### 二、SQL注入漏洞审计  
#### nickName参数SQL注入  
  
该项目使用了Mybatis来定义SQL，所以我们主要查看Myabatis中的Mapper文件中是否存在使用 $ 拼接SQL语句的情况，在Mapper文件中全局搜索${  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhrYZvaZpmXvnTAPc4gp4ZveqcuoaIl0WM5a7dcWYo2dznCs8E5AeXsQ/640?wx_fmt=png&from=appmsg "")  
  
1、查看UserMapper.xml文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhdILbSZvWhBjDI4morRYko8aZ2GtEboDloOzA4fjiaiaNPfsvRk0PWB3w/640?wx_fmt=png&from=appmsg "")  
  
2、可以看到nickName和userName使用了$拼接变量,有可能存在SQL注入漏洞，接下来我们挨个分析  
  
**nickName参数**  
  
先追踪到DAO层文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOho3hpYeufs5GMwEWC5qibH9fMHrVnA1zRJ4iaCKaaPOoLsQSEibt4ZpYUQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到getFuzzyUserByPage()方法中传入的参数是一个MyUser实体类，再查看这个实体类，在这个实体类中可以看到nickName和userName这两个参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhicpkNghAKDic3rZnOHibZRiab1WEDObOMqoI0N1dHAVwSeTslFC2Qpb3kQ/640?wx_fmt=png&from=appmsg "")  
  
继续往上跟，跟到实现层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhlbke9d2HDaK70m4G0CuzdamNp8xkeBQj65JJwy2sUEZ2o4BQ1PGOJA/640?wx_fmt=png&from=appmsg "")  
  
在  
UserServiceImpl  
类中调用了  
getFuzzyUserByPage()  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhZa2ExYyE3TiaTGibRKypSTPibqXo4zBBOQC09dP58wuX8bYvJFt1ZA6fg/640?wx_fmt=png&from=appmsg "")  
  
继续往上跟，来到service层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhlm4HHk71ON7LjLAhicWJQ3iajhvvFKvJBAssUe3H1QGSgmhbS6x3UDcg/640?wx_fmt=png&from=appmsg "")  
  
点进  
getAllUsersByPage()  
，可以发现直接来到的Controller层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOht7hrT7ZTmpRxmI7GP2cYygy8IcEtKzeknNoGgc3TbbuTg9iabFicWK6w/640?wx_fmt=png&from=appmsg "")  
  
并且根据这里的几个注解我们可以得出  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhAZMNMjGRSibnlZbuuvGEiaXgmMZiaM5OKMl0UjomPwG28tWoYKnqZ3lpA/640?wx_fmt=png&from=appmsg "")  
  
观察到UserController类被映射到了/api/user接口  
  
所以这里只要用户请求/api/user接口并带上MyUser实体类的参数，就会自动将该参数的值赋值给实体类new出来的对象myUser  
  
构造payload  
```
GET /api/user?page=1&limit=10&userName=1&nickName=1+AND+sleep(5) HTTP/1.1
Content-Type: application/json
Host: 127.0.0.1:8088
Cookie: JSESSIONID=C19E8EA001366E48547AC99F8980D962; remember-me=YWRtaW46MTcxOTczNDI5MjU0MDphYmM1YmE5OTdlNjMwMWYwMmE2MjU4OTMxZjEwYzFhOQ
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhOuFMSKBKEgKowBS5btpNYpibcyeG2JX7VQwlgauK5XfnB7b1P1aEtOQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh7n2SiaNJCyBzdoRiaFfowDaiahEHnTKRsOLfh9U6nExX10SibpyerJZGCQ/640?wx_fmt=png&from=appmsg "")  
#### userName参数SQL注入  
  
该SQL注入原理同上，不再叙述了  
  
payload  
```
GET /api/user?page=1&limit=10&nickName=1&userName=1+AND+(SELECT+9940+FROM+(SELECT(SLEEP(5)))rgGT) HTTP/1.1
Content-Type: application/json
Host: 127.0.0.1:8088
Cookie: JSESSIONID=C19E8EA001366E48547AC99F8980D962; remember-me=YWRtaW46MTcxOTczNDI5MjU0MDphYmM1YmE5OTdlNjMwMWYwMmE2MjU4OTMxZjEwYzFhOQ
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhzjj6RB7MBriamjRLLM3HVc6NYIiaBicvfxXfjVywZ4xY3ZmjY6q9LmoFQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhNibYHtrTpcYV0Z5ibpUwWvuTgF3KNPqkFSZHDEBjmzE3VRDUVmZicq1SA/640?wx_fmt=png&from=appmsg "")  
#### dictName参数SQL注入  
  
原理同上，根据以下路径跟踪即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh8XFqdTmdQ8F85LiczoU0icGpg7iczjC6fYz6Fka2UcxKYq2DVSVicUD9Tg/640?wx_fmt=png&from=appmsg "")  
  
payload  
```
GET /api/dict?page=1&limit=10&dictName=1+and+sleep(5) HTTP/1.1
Host: 127.0.0.1:8088
Accept: application/json, text/javascript, */*; q=0.01
Cookie: JSESSIONID=D38C3BF1CBEA080C39D38E1E2508BA9A; remember-me=YWRtaW46MTcxOTc1NDQyNDUyMzplMjBjNGFmYzUwODYzN2VlZThkNWNhMDY5ZWZlODhmZA
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhLgAU5B68HSTO3arljdAybrOaLAicMvdBWfuy7uEF0Oiag07umzJsiabicQ/640?wx_fmt=png&from=appmsg "")  
#### ancestors参数SQL注入  
  
1、Mapper层代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhOkiaGRXqASSlVlLHPxEHQDhP9Dz0S92cRBUDKv5U3yiacNeH7QnZdDSA/640?wx_fmt=png&from=appmsg "")  
  
2、追踪到DAO层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhHEf0ykRibGzGEnAdN7Oz9dpdjhOnzgPe2CAGkG8oOthLbKdd9dlragg/640?wx_fmt=png&from=appmsg "")  
  
3、实现层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhS1icSXgMCIAO9dLaXFHTmMhj4HT0mTdg3ssSWW9teiclEErYTicuo2OWg/640?wx_fmt=png&from=appmsg "")  
  
可以看到在实现层的  
updateParentDeptStatus()  
方法调用了  
updateDeptStatus()  
方法，我们再追踪到调用  
updateParentDeptStatus  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhoGKkJWheX252jVncIJDYRnKLU6fib4SdQBdC3OuSANCFF2UZRSorIlg/640?wx_fmt=png&from=appmsg "")  
  
4、可以看到在  
updateDept()  
方法中调用了  
updateParentDeptStatus  
方法，点进  
updateDept()  
方法，来到Controller层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhDzAQYgXKfbUvchEyzoSjFibzZj161jCpO2lWhIh6z7hwZ1fzWLSvGhQ/640?wx_fmt=png&from=appmsg "")  
  
5、可以看到Controller层代码处理了传入的  
Mydept  
对象，处理的过程中调用  
updateDept  
方法  
  
Mydept实体类的代码如下    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhoe0Gv2jwPWWucZsicvEhB4yEnCWrKK6tTJCRw54uBRiaVCN4uDj4q1TQ/640?wx_fmt=png&from=appmsg "")  
  
分析到这看起来是一个很平常的SQL注入，但是并不是，因为可以看以下代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhAk6ZugyBFp6z95WXxd3PvpzHcGrERYciaMkJT3h5HyiahTDQPBq3SoNA/640?wx_fmt=png&from=appmsg "")  
  
在实现层中传入了dept实例的dept_id属性值，并根据这个id值从数据库获取对应的dept实例，再将数据库获取的dept赋值为dept，所以这里覆盖了我们传入的dept实例。所以这里被覆盖之后dept的ancestors属性值就不会是我们传入的dept属性值了，而是根据传入的id值从数据库中取出来的，所以说在这里我们的ancestors值是不可控。  
  
那为什么说ancestors参数存在SQL注入漏洞呢？  
  
这里就需要注意一点，当某个存在SQL注入的参数在当前输入不可控时，可以找找其他地方，看能否通过其他功能修改该参数，从而使该参数可控  
  
那怎么找呢？找能够控制该参数的对应  
方法即可，例如这里参数不可控的原因是因为  
参数是从数据库取出来的  
，那我们就可以找找什么地方可以修改数据库中的这个值，即在对应的mapper文件中找找  
insert语句  
和  
update语句  
****  
  
这里共有三个update语句，并没有insert，所以下面我们来逐个看看这三个update语句  
##### 第一个update语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh2axptYU2tYDAM5MYHPgxuHMBKHrkichiafKaDjn5ZDQnIx8ogb9aleBg/640?wx_fmt=png&from=appmsg "")  
  
这个update语句是用于批量更新多个部门的ancestors, 但是它是通过  
where id in  
：指定条件，根据部门 id列表更新对应的记录，而且这个id我们是不可控的  
  
看看ChatGPT的解释  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh74SwNf0QDmX4BbB9ZS85NQWXHyLhIAFvbWfDC8q0r3S8iaKN6pFZLlg/640?wx_fmt=png&from=appmsg "")  
  
来到实现层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhicsJ0xhUdOZgjISQ63NhtHWicoJ4xF8xBrxpicuLShtBHqpladfibCx3Hw/640?wx_fmt=png&from=appmsg "")  
```
public int updateDept(MyDept dept) {
    // 获取父部门的信息
    MyDept parentInfo = deptDao.selectDeptById(dept.getParentId());
    // 获取当前部门的旧信息
    MyDept oldInfo = selectDeptById(dept.getDeptId());
    
    // 如果父部门信息和当前部门旧信息都不为空
    if (ObjectUtil.isNotEmpty(parentInfo) && ObjectUtil.isNotEmpty(oldInfo)) {
        // 生成新的ancestors，格式为：父部门的ancestors + 父部门的ID
        String newAncestors = parentInfo.getAncestors() + "," + parentInfo.getDeptId();
        // 获取旧的ancestors
        String oldAncestors = oldInfo.getAncestors();
        // 设置当前部门的ancestors为新的ancestors
        dept.setAncestors(newAncestors);
        // 更新当前部门的子部门的ancestors
        updateDeptChildren(dept.getDeptId(), newAncestors, oldAncestors);
    }
    
    // 更新当前部门信息
    int result = deptDao.updateDept(dept);
    
    // 如果当前部门的状态为正常
    if (UserConstants.DEPT_NORMAL.equals(dept.getStatus().toString())) {
        // 启用该部门的所有上级部门
        updateParentDeptStatus(dept);
    }
    
    // 返回更新操作的结果
    return result;
}
```  
  
该方法传入的ancestors是  
```
```  
  
显然我们要控制这里的ancestors是不可能的（因为部门id我们是不可控的）  
##### 第二个update语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhp9nBluLHdPcI8b2VbmI5oaicWOysicjNIMGiaJTmDG6JdXeWrHxzYb0qQ/640?wx_fmt=png&from=appmsg "")  
```
```  
  
这个update语句将数据库中指定id的dept信息换为传入的dept信息，其中就包含了ancestors参数，所以只要我们能够控制传入dept实例的ancestors属性值，就能够修改数据库中对应的ancestors，造成SQL注入漏洞  
  
看看ChatGPT的解释  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhfRiaQ6K03d6ebI6kj56rm4icjmqwZ8wC2IOc2ZsCkHnoP3NkupuiauUFw/640?wx_fmt=png&from=appmsg "")  
  
来到实现层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh9kckzico8Ekpa7scH4eibzE515rJDaJia6zQIGKA3gpFwGLz2c7eLlVMQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到实现类中，传入的dept对象如果有上级部门，并且当前dept对象不为空，就会进入到if条件，然后会去修改我们传入的dept对象的ancestors属性值  
  
如果我们想要控制ancestors，就不能让程序修改我们输入的ancestors属性值，也就不能满足if条件(上级部门信息和当前当前dept对象(部门信息)都不为空)  
```
```  
  
之后程序就会调用  
updateDept  
直接替换dept对象的信息到数据库中，我们继续向上追踪，来到Controller层    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhKn4VEMnYRZAylKE1xJfuaRLzibzD4CBOnnEEq3eJxx607ibQUCsyVRTA/640?wx_fmt=png&from=appmsg "")  
  
可以看到在Controller层中，经过一系列的if条件，然后调用了  
updateDept  
方法, 并且该方法对应程序中的"修改部门功能"  
> 经过上面的分析，我们确定这个位置是可以控制数据库中的ancestors值的，只需要在"修改部门"的请求中带上ancestors参数，并且当前部门没有上级部门时，我们输入的ancestors就会覆盖数据库中ancestors参数值，即实现了ancestors参数可控  
  
  
  
又因为刚才我们发现的SQL语句使用$拼接了ancestors参数,所以这里存在SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh9PiaMlfLRYsNYalwNOYViaUXjuteCeWJnzD6mZ3diaQ3qLmecvy58uWmA/640?wx_fmt=png&from=appmsg "")  
##### 第三个update语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhxJM9TqZcB7AJHbFpe6seiagia0iatdS4OsrpruK9rFqDGF42QiczYmpTiaw/640?wx_fmt=png&from=appmsg "")  
  
这个update语句不涉及ancestors参数，所以就不需要再分析  
  
看看ChatGPT的解释  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhb3xs8yNG2KoJBjTYMJzkMJcZ0XqKB6xYicC5k4GSaIDjjhJ2nibsNVrA/640?wx_fmt=png&from=appmsg "")  
### 三、漏洞复现  
  
这个漏洞点位于“修改部门‘功能，我们来到部门管理页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhRCibwES1MKd2p6M9okJXlTS3tamdVknrIw7cR5ftribVcYK5LiaIVpcmw/640?wx_fmt=png&from=appmsg "")  
  
选一个没有上级部门的部门进行修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhFyCuPqg8iaibAS0z7jIrA04zntPwSf2Qm4j7eK5Jt9rueHtEzic2IcM6w/640?wx_fmt=png&from=appmsg "")  
  
可以看到请求并没有携带ancestors参数，但是我们刚才分析此处是可以传入ancestors参数的，因为接收的是Mydept类  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhokKpzowY0DdgUwwIRibwl6yQNSYxicnTPaokT0nSibY6D9VwRwIalZUTg/640?wx_fmt=png&from=appmsg "")  
  
  
Mydept类有的属性都可以接收  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOhf0oiaY86fYibAOkWLFSCcSWoBP2CuZASnkDGH2GH9xKT4zaREZ3a1Scg/640?wx_fmt=png&from=appmsg "")  
  
构造payload  
```
PUT /api/dept HTTP/1.1
Host: 127.0.0.1:8088
Sec-Fetch-Mode: cors
Accept: application/json, text/javascript, */*; q=0.01
Cookie: JSESSIONID=966124AD0558B0F404998C6158F56C58; remember-me=YWRtaW46MTcxOTc1MDE1MjI2ODozYjliNWYzODZmNzczY2RkNmFhZDMwYzU4Mzg0M2FmZA
Sec-Fetch-Dest: empty
Sec-Fetch-Site: same-origin
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Content-Type: application/json


{"deptId":"1","deptName":"南京总公司","sort":"1","status":"1","parentId":"0","dataTree_select_nodeId":"","dataTree_select_input":"","ancestors":"1) and sleep(5)#"}
```  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b6UzoibqnYFEgg4LZNcMIahHib6DcjZUOh23Fia4MicRd6ozvhUfg0Fc7GzARt7C2fiaMaOnQswOo92ibZGsicvqvos3w/640?wx_fmt=png&from=appmsg "")  
### 四、参考链接  
```
```  
  
