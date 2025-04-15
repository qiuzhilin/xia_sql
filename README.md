# xia SQL (瞎注)

> 本插件仅只插入单引号，没有其他盲注啥的，且返回的结果需要人工介入去判断是否存在注入，如果需要所有注入都测试，请把burp的流量转发到xray。

## 注意
* 默认使用jdk1.8编译
* 在最新版的burp2.x中jdk为1x,会导致插件不可用,请下载jdk16版本试试,若还不行，请自行下载源码使用当前电脑的jdk1x进行编译,谢谢。

***********

* burp 插件。
* 在每个参数后面填加一个单引号，两个单引号,如果值为纯数字则多加一个-1、-0。
* 由于不会java，且又是用java写的，代码太烂，勿喷。`
* 感谢名单：Moonlit、阿猫阿狗、Shincehor、Xm17

***********

## 插件使用描述
* 返回 `✔️` 代表两个单引号的长度和一个单引号的长度不一致，`表明可能存在注入`。
* 返回 `✔️ ==> ？` 代表着 原始包的长度和两个单引号的长度相同且和一个单引号的长度不同，`表明很可能是注入`。
* 返回 `Err` 代表响应包中含有数据库报错信息。
* 返回 `diy payload` 代表自定义的payload。
* 返回 `time > 3` 代表访问网站的时间大于3秒，可利用该功能配合自定义payload功能测试`时间盲注`。
* 支持json格式，V1.9以上版本`已支持json多层嵌套`。
* 支持参数的值是`纯数字则-1，-0`。
* 支持cookie测试
* 支持`右键发送到插件扫描`（哪怕之前扫描过的，仍然可以通过右键发送再次扫描）备注：右键发送一定需要有响应包，不然发不过去，这样才能对比和原数据包的长度。
* 支持`自定义payload`。
* 支持自定义payload中的参数值`置空`。
* 监控Proxy流量。
* 监控Repeater流量。
* 同个数据包只扫描一次，算法：`MD5(不带参数的url+参数名+POST/GET)`。
* 支持白名单功能，若多个域名请用,隔开

## 插件截图

<img width="1526" alt="image" src="https://user-images.githubusercontent.com/30351807/217544602-fc770d5a-235d-4f2d-b636-c782a6c222c6.png">
**********

### 2025-4-15
#### xia SQL 4.2
##### 优化：
* 修复json体参数注入bug
* 支持自定义json体payload的层级，防止超深度带来的性能问题
##### 新增：
* 新增时间盲注支持
* 时间盲注的判断条件：payload数组中只能有一个元素，并包含sleep  waitfor字符串 例如：["'||pg_sleep(3)--"]
* 如果payload 响应时间超过 延迟的时间，判定为可能存在注入，
**********

### 2025-4-9
#### xia SQL 4.1
##### 优化：
* 支持额外参数组合，参考样例：pageNum=1&pageSize=5&orderByColumn=aaa
* 额外参数支持应用到POST请求，json体，目前，额外参数只追加到json体的第一层
* 取消额外参数应用payload
* 修复json 体无法注入payload的bug,重构json参数注入逻辑
**********

### 2025-4-3
#### xia SQL 4.0
##### 新增：
* 允许自动添加额外的参数以及数值
* poc应该成对存在,然后比对poc返回不同的数据,可自定义输入成对的poc
##### 优化：
* 优化检测白名单：String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi","webp","woff","woff2","doc","docx","csv","xls","xlsx","map","svg"};。
* 左上侧请求日志表格可拖拉
* 原始包长度全局变量original_data_len线程安全问题
##### 应用说明:
* payload 配置框:
* 配置的格式为:    ["payload1","payload2"];;;正则表达式
* 如果中括号里面的payload值只有1个，会将该payload 请求返回的报文长度与原始流量对比，如果长度不一致，状态设置为存疑,
* 如果中括号里面的payload值为2个，会比对两个payload请求的长度和原始报文的长度，比对逻辑与3.3版本的一致。poc返回不同的数据
* 也支持配置3个以上，但是目前 第2个起的只会与第一个payload比对。
* ;;; 分隔符后面是正则表达式，如果参数的value值匹配上这个正则表达式才会执行该行的payload
* 例如：["-0","-1"];;;[0-9]+     "-0","-1"这两个payload只会应用到value是数值类型的参数上。
**********
* 自定义额外参数 配置框:
* 额外参数目前只对 GET请求起作用
* 配置的格式为:  key=value
* 如果勾选开启额外参数单选框，会在原始请求url后拼接上自定义的参数。
* 如果勾选额外参数应用payload 单选框，除了在原始请求url后拼接上自定义的参数，还会将配置的payload应用到自定义的参数上。
* 点击持久化额外参数按钮，会将当前自定义参数的配置持久化到本地。
![image](https://github.com/user-attachments/assets/72dbbb95-71f1-45a7-a707-74f917f1f534)




**********
### 2023-5-18
#### xia SQL 3.3
* 优化响应包的内容为图片时，忽略处理。

**********
### 2023-3-6
#### xia SQL 3.2
* 优化左上的两个窗口可以在内部可伸缩
* 启动自定义payload后，取消内置payload。

<img width="1591" alt="image" src="https://user-images.githubusercontent.com/30351807/223004986-91c728db-3dde-4794-8792-49c73ce91b87.png">


**********
### 2023-2-10
#### xia SQL 3.1
* 更新自定义数据库报错关键字。
* 更新日志模式，里面输出的是哪条数据库报错关键字触发的。

<img width="1538" alt="image" src="https://user-images.githubusercontent.com/30351807/218113665-4d0e5f33-6bf8-44d9-80ff-11a703f3f024.png">

<img width="594" alt="image" src="https://user-images.githubusercontent.com/30351807/218115763-2e32a58f-e183-48b7-85e1-fc5d45e359c3.png">



**********
### 2023-2-8
#### xia SQL 3.0
* 新增匹配响应包是否有包含数据库报错关键字，如有将显示Err
* 优化请求包的body内容为二进制时，过滤掉。

<img width="1526" alt="image" src="https://user-images.githubusercontent.com/30351807/217544602-fc770d5a-235d-4f2d-b636-c782a6c222c6.png">

<img width="500" alt="image" src="https://user-images.githubusercontent.com/30351807/217544699-1b4c3a9b-60d0-4068-b4ca-f6adaa2b5d83.png">


**********
### 2022-11-19
#### xia SQL 2.9
* 支持多个域名白名单
* 优化ui

<img width="600" alt="image" src="https://user-images.githubusercontent.com/30351807/202838425-bdadb2c7-0cb3-4b83-8837-b0e203df2457.png">


**********
### 2022-10-17
#### xia SQL 2.8
* 新增自定义payload保存到本地，每次打开burp将会自动获取上次保存的payload。

<img width="671" alt="image" src="https://user-images.githubusercontent.com/30351807/196190603-d2d49b42-9464-4308-bc91-dd695693c156.png">


**********
### 2022-8-7
#### xia SQL 2.7
* 修复2.6版本处理json格式致命错误
* 优化json嵌套格式处理，基本上都能正确处理，除个别极端情况
* 新增响应码列
* 新增白名单功能。

<img width="1431" alt="image" src="https://user-images.githubusercontent.com/30351807/183281150-453ac528-0da1-4f56-a290-dd7a6455ee15.png">



**********
### 2022-6-22
#### xia SQL 2.6
* 新增变化中具体长度变化多少的值（如果变化的值小于等于4基本上是误报）
* 修复已知bug

<img width="1195" alt="image" src="https://user-images.githubusercontent.com/30351807/174960597-28cc6362-27ea-4015-ab21-fc8086d9ee1d.png">


**********
### 2022-6-6
#### xia SQL 2.5
* 修复burp2.x json嵌套bug


**********
### 2022-5-27
#### xia SQL 2.4
* 新增支持对cookie测试

![image](https://user-images.githubusercontent.com/30351807/170674995-f5595cc4-afe6-4d74-97d3-6175c4966519.png)


**********
### 2022-5-24
#### xia SQL 2.3
* 新增 状态一列，`run……` 表示正在发送相关payload，`end!` 表示已经扫描完成，`end! ✔️`表示扫描完成且结果可能存在注入。

![image](https://user-images.githubusercontent.com/30351807/169846432-106a0764-7f20-466e-831d-8b8615c9dda7.png)


**********
### 2022-5-20
#### xia SQL 2.2
* 优化proxy模式有时流量不过来问题。
* 优化Proxy、Repeater 模式下，静态资源不处理。后缀：jpg、png、gif、css、js、pdf、mp3、mp4、avi`(右键发送不影响)`

![image](https://user-images.githubusercontent.com/30351807/169476496-e2a7351b-f701-42f8-b56b-a8d411ab6eca.png)


**********
### 2022-5-12
#### xia SQL 2.1
* 新增 自定义payload中参数值置空

![image](https://user-images.githubusercontent.com/30351807/168087873-1e57c10d-cf66-4783-af1e-3d075f629c4d.png)

**********
### 2022-4-25
#### xia SQL 2.0
* ui界面优化
* 添加自定义payload功能
* 自定义payload访问网站时间大于3秒，将显示 time > 3。

![image](https://user-images.githubusercontent.com/30351807/165055862-c0a3a72e-918c-47b7-84ad-f74b1cb2f365.png)

![image](https://user-images.githubusercontent.com/30351807/165055655-1ac9b40a-4c68-424a-b73e-f31b3b5f1162.png)

**********
### 2022-4-11
#### xia SQL 1.9
* 支持json多层嵌套
* 新增列：用时，用于后期更新自定义payload时，可以查看到每个数据包所用的时间。
![image](https://user-images.githubusercontent.com/30351807/162653146-5caaf300-3b1c-4680-af06-e84364a5e3b4.png)


**********
### 2022-4-8
#### xia SQL 1.8
* 新增右键发送到插件扫描
* 优化 监控Repeater 模式下数据包返回速度。
![image](https://user-images.githubusercontent.com/30351807/162444663-ecc491e2-9a74-4d0f-8b1f-c6ce8f61546a.png)


**********
### 2022-4-2
#### xia SQL 1.7
* 修复在burp2.x版本下poxry模式展示内容bug
![image](https://user-images.githubusercontent.com/30351807/161375553-cee2df69-5681-4818-95ae-0ed389795ea4.png)


**********
### 2022-3-31
#### xia SQL 1.6
* 更新相同数据包只扫描一次的算法，算法：MD5(不带参数的url+参数名+POST/GET)
![image](https://user-images.githubusercontent.com/30351807/161045937-d0e3584a-d610-4b26-ba33-6cc08dd9e8fa.png)


**********
### 2022-3-29
#### xia SQL 1.5
* 取消默认选中“监控Repeater”，增加默认选中“值是数字则进行-1、-0”。
* 变更 监控Proxy模式 为被动模式，提升交互体验感。
* 新增相同数据包只扫描一次。算法：MD5(url+参数名)，如果是post包，值变化也不会重新扫描，需要参数名变化才会再次扫描。


**********
### 2022-2-13
#### xia SQL 1.4
* 更新了 一个选项，如果值是纯数字的话就进行-1，-0
![image](https://user-images.githubusercontent.com/30351807/153725862-8ec9e92f-66b5-4d5c-9c3e-fb18f5afaa94.png)


**********
### 2022-2-11
#### xia SQL 1.3
* 更新了 原始包的长度和两个单引号的长度相同且和一个单引号的长度不同就返回 ✔️ ==> ？

![image](https://user-images.githubusercontent.com/30351807/153590052-42293c4a-7a85-4740-b29e-209a7c27d403.png)


**********
### 2022-2-11
#### xia SQL 1.2
* 更新支持json格式

![image](https://user-images.githubusercontent.com/30351807/153567877-479a0e15-9d6c-43f5-84d9-80c5dfb6fd03.png)


**********
### 2022-2-10
#### xia SQL 1.1
* 更新了序列号
* 更新了有变化 打勾
* 更新了如果那个数据包没有参数，那就忽略。这样开 proxy 模式 就不会一堆包了。

![image](https://user-images.githubusercontent.com/30351807/153390045-2b3769f6-151b-45c0-a555-53cda4fef2f2.png)


**********
# 图片展示

![image](https://user-images.githubusercontent.com/30351807/153139897-08e6b69b-f129-4fab-a62e-037351d7c60f.png)

![image](https://user-images.githubusercontent.com/30351807/153139950-a4f51f4b-e39d-459d-91b8-e326c2c74c29.png)


![image](https://user-images.githubusercontent.com/30351807/153139522-b9af5d35-36a3-4204-b2f4-7b6a11253d41.png)
