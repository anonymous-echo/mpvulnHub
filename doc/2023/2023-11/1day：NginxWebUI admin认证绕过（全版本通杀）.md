#  1day：NginxWebUI admin认证绕过（全版本通杀）   
原创 uname  黑伞安全   2023-11-27 17:00  
  
本文报道了一个关于 Admin 类型可注入 autoKey 绕过认证的问题。  
文章描述了在 AdminController.java 中的 changePassOver() 方法和 addOver() 方法中，如何通过判断 admin.getId() 来决定是否对 admin 进行修改密码和添加用户的操作。  
同时，文章还提到了在 getByAutoKey() 方法中如何获取 admin 实例，并进行相应的操作。  
  
文章速读  
  
Admin类型注入autoKey绕过认证、  
绕过密码和Google认证获取管理员权限  
  
这一章节描述了一个名为nginxWebUI的软件中的一个漏洞，该漏洞可以通过注入autoKey绕过认证。攻击者可以利用这个漏洞在系统中执行恶意操作，并且不需要输入正确的用户名和密码。为了防止这种漏洞被利用，开发人员需要加强对系统的安全性检查和防范措施。同时，用户也应该注意保护自己的账号信息，避免被黑客攻击。  
攻击者可以通过向数据库注入autoKey来绕过密码和Google认证，并使用autoLogin接口获得管理员认证。  
该漏洞存在于两个路由中，即changePassOver和addOver。  
攻击者只需要在发送数据包时包含autoKey，就能成功注入到数据库。  
漏洞的发现是通过测试来实现的，最终的结果是在成功注入到数据库后，可以使用autoLogin接口获取管理员认证。  
  
  
**审计过程：**  
  
com/cym/controller/adminPage/AdminController.java#changePassOver()  
```
  @Mapping("changePassOver")
  public JsonResult changePassOver(Admin admin) {

    adminService.changePassOver(admin);

    return renderSuccess();
  }
```  
```
  public void changePassOver(Admin admin) {
    if (admin.getAuth()) {
      Admin adminOrg = sqlHelper.findById(admin.getId(), Admin.class);
      if (StrUtil.isEmpty(adminOrg.getKey())) {
        admin.setKey(authUtils.makeKey());
      }
    } else {
      admin.setKey("");
    }

    if (StrUtil.isNotEmpty(admin.getPass())) {
      admin.setPass(EncodePassUtils.encode(admin.getPass()));
    } else {
      admin.setPass(null);
    }
    sqlHelper.updateById(admin);

  }
```  
  
这里也是对admin.getId()判断，然后来改密码。  
  
com/cym/controller/adminPage/AdminController.java  
```
  @Mapping("addOver")
  public JsonResult addOver(Admin admin, String[] parentId) {
    if (StrUtil.isEmpty(admin.getId())) {
      Long count = adminService.getCountByName(admin.getName());
      if (count > 0) {
        return renderError(m.get("adminStr.nameRepetition"));
      }
    } else {
      Long count = adminService.getCountByNameWithOutId(admin.getName(), admin.getId());
      if (count > 0) {
        return renderError(m.get("adminStr.nameRepetition"));
      }
    }

    adminService.addOver(admin, parentId);

    return renderSuccess();
  }
```  
  
添加用户的路由, 可以控制admin，parentId，admin.getId()是否为空，不为空进入adminService.getCountByName，跟进getCountByName()  
  
com/cym/service/AdminService.java#getCountByName  
```
  public Long getCountByName(String name) {
    return sqlHelper.findCountByQuery(new ConditionAndWrapper().eq(Admin::getName, name), Admin.class);
  }
```  
  
可以看到进行sql查询，查看数据库是否存在用户。不存在此用户就在service层面创建用户，跟进adminService.addOver。  
  
com/cym/service/AdminService.java#addOver()  
```
  public void addOver(Admin admin, String[] groupIds) {
    sqlHelper.insertOrUpdate(admin);

    sqlHelper.deleteByQuery(new ConditionAndWrapper().eq(AdminGroup::getAdminId, admin.getId()), AdminGroup.class);
    if (admin.getType() == 1 && groupIds != null) {
      for (String id : groupIds) {
        AdminGroup adminGroup = new AdminGroup();
        adminGroup.setAdminId(admin.getId());
        adminGroup.setGroupId(id);
        sqlHelper.insert(adminGroup);
      }
    }
  }
```  
  
这个方法直接将admin添加到数据库，deleteByQuery就是根据admin_id删除admin_group的数据，不重要，dmin.getType() == 1就是非管理员，管理员的type为0，不会走到这里。  
  
以上两个路由都接收的Admin admin，  
  
com/cym/model/Admin.java  
```
public class Admin extends BaseModel {
  String name;
  String pass;
  // 谷歌秘钥
  String key;
  // 是否开启谷歌验证
  @InitValue("false")
  Boolean auth;

  // 是否开启api
  @InitValue("false")
  Boolean api;

  String token;
  // 自动登录key
  String autoKey;
  
  // 类型 0 超管 1 受限用户
  @InitValue("0")
  Integer type;
```  
  
admin类型里面包含了自动登录key，autoKey。  
  
com/cym/controller/adminPage/LoginController.java  
```
@Mapping("autoLogin")
public JsonResult autoLogin(String autoKey) {

   // 用户名密码
   Admin admin = adminService.getByAutoKey(autoKey);
   if (admin != null) {
      // 登录成功
      Context.current().sessionSet("localType", "local");
      Context.current().sessionSet("isLogin", true);
      Context.current().sessionSet("admin", admin);
      Context.current().sessionRemove("imgCode"); // 立刻销毁验证码

      // 检查更新
      versionConfig.checkVersion();

      return renderSuccess(admin);
   } else {
      return renderError();
   }

}
```  
  
这个功能点可以直接登录，什么二次验证都不用管。  
  
com/cym/service/AdminService.java#getByAutoKey  
```
  public Admin getByAutoKey(String autoKey) {
    return sqlHelper.findOneByQuery(new ConditionAndWrapper().eq(Admin::getAutoKey, autoKey), Admin.class);
  }
```  
  
就是从数据库取autokey。  
  
所以以上changePassOver，addOver两个路由，在发送数据包的时候只要autoKey，直接就可以注入到数据库，然后通过autoLogin接口传入autoKey即可通过认证，绕过密码、google认证。  
### 漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickA9QxoVusxiacibAg3LerLmWtIX2KAWHl9mkqlKIt4AViaCLibGQDhLKUNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickAGibiaYeiaDLlPIpJiaySO4e2ojl4o9RPa8eV5zH2X5HlUjG7N5xL874jQ/640?wx_fmt=png&from=appmsg "")  
  
成功注入到数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickAB1U0e5A3QMKQYpflJA5SSY2qkwdtQQuBK4jsqOVoqy5ctN49tmElQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickHAaTej4KkBtcRTjertdRh0iavrcdT5JjyQXJ9tegs7Ut7IKiaATgA6CA/640?wx_fmt=png&from=appmsg "")  
  
成功注入到数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickicvIbMNd32WeTl5Wjn54r2hIibAvfU2YRos2icaFgpdvpd3b9uBwx062Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicickhpaYTXNg5iafXgLgWTm0Xycsgaicicw6Ew6M0nXYUJicyCKdRqWWhX2Y5g/640?wx_fmt=png&from=appmsg "")  
  
然后调用autoLogin接口，即可获取admin认证。后面就可以利用nginxwebui的命令执行等功能为所欲为了。  
  
已经提交issues，issues如下：  
https://github.com/cym1102/nginxWebUI/issues/116  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrrw2puXa4iaT4BXhCjvYicick0iaglhicib90dp03LmPr1pcODD17uatvlicJcmzm0uPeLd2LrJGKkcmtZQ/640?wx_fmt=png&from=appmsg "")  
  
  
