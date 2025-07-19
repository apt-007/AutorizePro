# Gemini API 集成文档

## 概述

AutorizePro 现已支持 Google Gemini API，为用户提供更多的 AI 分析选择。

## 支持的 Gemini 模型

- `gemini-1.5-flash` - 快速响应模型，适合实时分析
- `gemini-1.5-pro` - 高质量分析模型，准确性更高
- `gemini-2.0-flash-exp` - 实验性的最新模型

## 配置步骤

### 1. 获取 Gemini API Key

1. 访问 [Google AI Studio](https://aistudio.google.com/)
2. 登录您的 Google 账户
3. 创建新的 API Key
4. 复制生成的 API Key

### 2. 在 AutorizePro 中配置

1. 打开 AutorizePro 插件的配置页面
2. 选择或输入 Gemini 模型名称（如 `gemini-1.5-flash`）
3. 在 API Key 字段中粘贴您的 Gemini API Key
4. 勾选复选框启用 AI 分析功能

## 技术实现细节

### API 端点
- 使用 Google Generative AI REST API
- 端点：`https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`

### 认证方式
- 使用 API Key 作为 URL 参数进行认证
- 格式：`?key={your_api_key}`

### 请求格式
Gemini 使用与其他模型不同的请求格式：

```json
{
    "contents": [
        {
            "parts": [
                {
                    "text": "system_prompt + user_prompt"
                }
            ]
        }
    ],
    "generationConfig": {
        "temperature": 0.1,
        "maxOutputTokens": 1024
    }
}
```

### 响应解析
- 支持 Gemini 特有的响应格式
- 自动提取文本内容中的分析结果
- 兼容标准的 JSON 格式输出

## 使用建议

1. **模型选择**:
   - 对于快速响应需求，推荐使用 `gemini-1.5-flash`
   - 对于高准确性需求，推荐使用 `gemini-1.5-pro`

2. **成本控制**:
   - Gemini API 按请求计费
   - 建议在测试前配置合适的域名过滤规则

3. **性能优化**:
   - 插件内置了响应缓存机制
   - 相同的请求对比不会重复调用 API

## 故障排除

### 常见问题

1. **API Key 无效**
   - 确认 API Key 格式正确
   - 检查 API Key 是否已激活

2. **模型不存在**
   - 确认模型名称拼写正确
   - 检查您的账户是否有权限访问该模型

3. **网络连接问题**
   - 确认可以访问 Google API 服务
   - 检查企业网络是否有防火墙限制

### 调试建议

- 查看插件日志输出，包含详细的 API 请求和响应信息
- 使用浏览器开发者工具检查网络请求
- 确认配置的模型名称与 Google AI Studio 中的一致

## 与其他模型的对比

| 特性 | Gemini | GPT | Qwen | GLM |
|------|---------|-----|------|-----|
| 响应速度 | 快 | 中等 | 快 | 中等 |
| 准确性 | 高 | 高 | 高 | 中等 |
| 成本 | 中等 | 高 | 低 | 低 |
| 可用性 | 全球 | 受限 | 中国 | 中国 |

## 更新日志

### v1.6.0
- 新增 Gemini API 支持
- 支持 gemini-1.5-flash、gemini-1.5-pro、gemini-2.0-flash-exp 模型
- 优化了 API 请求格式和响应解析逻辑
    </p>


##  🤗 鸣谢
**本产品基于 [Autorize](https://github.com/Quitten/Autorize) 插件开发，感谢 Barak Tawily。**

## 📑 Licenses

在原有协议基础之上追加以下免责声明。若与原有协议冲突均以免责声明为准。

<u>在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。禁止用于未经授权的渗透测试，禁止二次开发后进行未经授权的渗透测试。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，开发者将不承担任何法律及连带责任。</u> 

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
