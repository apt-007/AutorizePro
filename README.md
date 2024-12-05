![image](https://github.com/user-attachments/assets/26959ef1-1629-4f6b-9dbc-68e1cd0099b7)

- [English README IS HERE](https://github.com/sule01u/AutorizePro/blob/master/README_en.md)

# 🧿 AutorizePro (内置AI分析模块 ❤️‍🔥):  
### 一句话介绍工具： AutorizePro 是一款创新性的内置AI分析模块的专注于越权检测的 Burp 插件 (已有多个白帽反馈用工具嘎嘎挖到src洞, 每周末更新, 欢迎Star🌟以便持续跟踪项目最新版本功能)
> **🟣️ 未点击启用AI功能时走正常检测逻辑，AI为可选项。由于接口响应一般多种多样，规则难以覆盖；启用AI分析会大幅提升检出效率以及准确率，强烈建议试试！！时间是宝贵的，我们应该尽量让AI来替我们做那些耗时且重复的工作，快来十倍速挖洞吧！**

### 工具背景
- **越权漏洞在黑盒测试、SRC挖掘中几乎是必测的一项，但手工逐个测试越权漏洞往往会耗费大量时间。**
- **而自动化工具又因为接口的多样化，难以制定一个全面的检测逻辑而存在大量误报, 基于此产生了 AI辅助分析的检测工具 ➡️ AutorizePro !! ⬅️**

### 工具亮点
- **优化检测逻辑 && 增加 AI 分析模块(可选项) ，将工具原始误报率从 99% 降低至 5% ，从海量误报中解脱出来**
- **对于需要人工确认的告警可通过展示页面并排查看 原始请求、越权请求 以及 未授权请求 的数据包方便对比差异**
- **支持多种自定义的配置项，如过滤器配置、替换规则配置、导出报告、支持多种大模型分析 ( 默认为YYDS的通义千问 ) 等**


## 🔧 安装AutorizePro
### 1️⃣ 下载 Burp Suite 和 Jython

    1. 下载 Burp Suite：https://portswigger.net/burp/releases
    2. 下载 Jython standalone JAR 文件：https://www.jython.org/download.html

### 2️⃣ 配置 Burp Suite 的 Python 环境

	1. 打开 Burp Suite
	2. 导航到 Extender -> Options
	3. 在 Python Environment 部分，点击 Select File
	4. 选择你刚刚下载的 Jython standalone JAR 文件 (本项目测试环境为: jython 2.7.3, burp suite 2024.11（自带的java版本为java22）)

### 3️⃣ 安装 AutorizePro 插件
	1. 下载代码仓库最新版本的发布zip包到本地，解压
    2. 打开 Burp Suite，导航到 Extender -> Extensions -> Add
    3. 在 Extension Type 选择框中，选择python
    4. 在 Extension file 选择框中，选择代码仓库中 AutorizePro.py 文件路径 (注意路径不能有中文，否则安装失败)

### AutorizePro 插件安装完成界面 🎉
> 💡 你可通过拉动中间的侧边栏调整展示页和配置页的显示比例；配置界面可通过上下拉动分界线调整配置页面比例；

![cover](imgs/cover.png)

## 🔫 使用 AutorizePro 插件
    1. 打开配置选项卡：点击 AutorizePro -> Configuration。

    2. 通过fetch cookie header按钮获取最新请求的验证头 或 手动复制低权限用户的验证头（通常是 Cookie 或 Authorization），并将其复制到标有 “Insert injected header here” 的文本框中。注意：如果请求中已经包含了该头部，插件会替换现有的头部，否则会添加新头部。

    3. 如果不需要进行未授权的测试（即不带任何 cookie 的请求，用于检查接口是否存在身份验证，而不仅仅是低权限用户的越权检测），可以取消勾选 Check unauthenticated (默认开启)。

    4. 勾选 Intercept requests from Repeater，通过 Repeater 发送的请求也会被进行插件处理。

    5. 点击 AutorizePro is off 按钮启用插件，让 AutorizePro 开始拦截流量，并进行授权检测。

    6. 打开浏览器，并配置代理设置，使流量能够通过 Burp 代理。

    7. 使用高权限用户访问你想测试的应用程序，测试修改类资源时可使用 Match/Replace 配置越权测试时需要修改的资源信息。

    8. 在 AutorizePro 插件的左侧结果展示界面中，你将看到请求的 URL 和 对应的权限检查状态。
    
    9.  选择模型，填写对应api key; 

    10. 勾选复选框后，启用 Key 时，符合AI分析触发条件的请求会交由 AI 进一步分析，结果将展示在 AI. Analyzer 列。

    11. 点击左侧展示页面的某个 URL，可以查看它的原始请求、修改后的请求以及未经身份验证的请求/响应，方便你分辨差异。

###  🌠 使用效果示例
>  🌟 大幅降低误报: 从下图中可以看出，启用AI分析后，你只需要去分析一个请求是否真正越权，人工投入的分析精力节约95%以上。

> ⬇️ 替换cookie方式测试越权

![eg](imgs/eg.png)

> ⬇️ 替换参数方式测试越权

![eg](imgs/eg2.png)

> 查看选中条目的具体请求信息，可同时展示越权请求、原始请求、未授权请求，方便对比差异

![response](imgs/response.png)

### ❓检测状态说明
- **Bypassed! (红色) : 判定越权**

- **Enforced! (绿色) : 判定不存在越权**

- **Is enforced??? (please configure enforcement detector): 无法判断，可以在 enforcement detector 进一步配置越权特征协助判断**

```
🌟 Tips:

    Is enforced??? 状态表示插件无法确定接口是否做了权限控制，可通过 enforcement detector 进一步配置权限校验特征来辅助判断 或 启用AI来辅助分析。

    eg:
    如果某个接口对于越权访问请求会返回 "无权限" 这个指纹特征，
    你就可以将这个指纹特征添加到 Enforcement Detector 过滤器中，这样插件判断时就会查找这个指纹特征，区分出实际已鉴权的接口，减少误报。
```

### 🚰 过滤器配置：在 Interception Filters 配置拦截规则

- 拦截过滤器位可以配置插件需要拦截哪些域名 或 拦截符合指定特征的请求。
- 你可以通过黑名单、白名单、正则表达式或 Burp 的范围内的项目来确定拦截的范围，以避免不必要的域名被 AutorizePro 拦截，避免对无关请求的拦截分散分析精力。
- ⚠️ ⚠️ **安全提示：因为工具涉及cookie替换重放，强烈建议 在 Interception Filters 指定目标的站点，以免cookie泄漏至其他站点** ⚠️ ⚠️ 
- 🌟 默认配置会避免拦截脚本和图片，你也可以新增更多静态资源类型的忽略规则。

##  💰 AI分析功能需要花多少钱？(默认根据工具检测逻辑判断，AI需要用户启用之后才会生效)
- 启用AI分析之后仅自动检测 (状态码相等 && 响应为json格式 && 响应长度在50-6000 的数据包);若不符合条件，AI分析功能将不会生效，减少不必要的AI分析带来的经费消耗。
-  ⚠️ 注意：当启用AI分析功能时，您应该尽量在 Interception Filters 中配置拦截的 域名 / 规则，以免检测非目标站点带来的经费消耗。
- AI分析功能需要先开通模型调用服务，在 [阿里云百炼首页顶部提示](https://bailian.console.aliyun.com/#/home) 进行开通：
![tongyi](imgs/tongyi.png)
- [阿里云通义千问API计费说明，新开通的都有 100万tokens 的免费额度](https://help.aliyun.com/zh/model-studio/billing-for-model-studio) ( 个人测试消耗示例：在插件开发调试期间全天较高频率测试且没有限制域名，全天消耗总费用**0.38元**)
- 要使用其他模型，请自行查询并开通对应的服务以及申请API KEY。
<p>
    <img alt="AIFee" src="https://suleo.wang/img/AutorizePro/ai_fee.jpg" width="30%" height="30%" style="max-width:20%;">
</p>

## ⛪ Discussion
* 欢迎讨论任何关于工具相关的问题[点我](https://github.com/sule01u/AutorizePro/discussions)
* Bug 反馈或新功能建议[点我](https://github.com/sule01u/AutorizePro/issues)
* 欢迎 PR
* 微信公众号: **扫码关注不懂安全获取更多安全分享**
<p>
    <img alt="QR-code" src="https://suleo.wang/img/mine.png" width="30%" height="30%" style="max-width:20%;">
</p>


##  🤗 鸣谢
**本产品基于 [Autorize](https://github.com/Quitten/Autorize) 插件开发，感谢 Barak Tawily。**

## 📑 Licenses

在原有协议基础之上追加以下免责声明。若与原有协议冲突均以免责声明为准。

<u>在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。 禁止用于未经授权的渗透测试，禁止二次开发后进行未经授权的渗透测试。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，开发者将不承担任何法律及连带责任。</u> 

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
