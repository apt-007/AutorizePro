#!/usr/bin/env python3
# coding: utf-8

"""
@File   : authorization.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   : 
"""
import sys
import re
import datetime
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter, EOFException, IOException
from java.lang import StringBuilder
from javax.swing import SwingUtilities
from javax.net.ssl import SSLHandshakeException

reload(sys)

if (sys.version_info[0] == 2):
    sys.setdefaultencoding('utf8')

sys.path.append("..")

from helpers.http import (
    get_authorization_header_from_message,
    get_cookie_header_from_message,
    isStatusCodesReturned,
    makeMessage,
    makeRequest,
    getRequestBody,
    getResponseBody,
    IHttpRequestResponseImplementation
)

from gui.table import LogEntry, UpdateTableEDT


def tool_needs_to_be_ignored(self, toolFlag):
    for i in range(0, self.IFList.getModel().getSize()):
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore spider requests":
            if toolFlag == self._callbacks.TOOL_SPIDER:
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore proxy requests":
            if toolFlag == self._callbacks.TOOL_PROXY:
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore target requests":
            if toolFlag == self._callbacks.TOOL_TARGET:
                return True
    return False


def capture_last_cookie_header(self, messageInfo):
    cookies = get_cookie_header_from_message(self, messageInfo)
    if cookies:
        self.lastCookiesHeader = cookies
        self.fetchCookiesHeaderButton.setEnabled(True)


def capture_last_authorization_header(self, messageInfo):
    authorization = get_authorization_header_from_message(self, messageInfo)
    if authorization:
        self.lastAuthorizationHeader = authorization
        self.fetchAuthorizationHeaderButton.setEnabled(True)


def valid_tool(self, toolFlag):
    return (toolFlag == self._callbacks.TOOL_PROXY or
            (toolFlag == self._callbacks.TOOL_REPEATER and
             self.interceptRequestsfromRepeater.isSelected()))


def handle_304_status_code_prevention(self, messageIsRequest, messageInfo):
    should_prevent = False

    if self.prevent304.isSelected():
        if messageIsRequest:
            requestHeaders = list(self._helpers.analyzeRequest(messageInfo).getHeaders())
            newHeaders = []

            for header in requestHeaders:
                if "If-None-Match:" not in header and "If-Modified-Since:" not in header:
                    newHeaders.append(header)
                    should_prevent = True

        if should_prevent:
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            bodyBytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]

            bodyStr = self._helpers.bytesToString(bodyBytes)

            messageInfo.setRequest(self._helpers.buildHttpMessage(newHeaders, bodyStr))


def message_not_from_autorize(self, messageInfo):
    return self.replaceString.getText() not in self._helpers.analyzeRequest(messageInfo).getHeaders()


def no_filters_defined(self):
    return self.IFList.getModel().getSize() == 0


def message_passed_interception_filters(self, messageInfo):
    urlString = str(self._helpers.analyzeRequest(messageInfo).getUrl())
    reqInfo = self._helpers.analyzeRequest(messageInfo)
    reqBodyBytes = messageInfo.getRequest()[reqInfo.getBodyOffset():]
    bodyStr = self._helpers.bytesToString(reqBodyBytes)

    resInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
    resBodyBytes = messageInfo.getResponse()[resInfo.getBodyOffset():]
    resStr = self._helpers.bytesToString(resBodyBytes)

    message_passed_filters = True
    for i in range(0, self.IFList.getModel().getSize()):
        interceptionFilter = self.IFList.getModel().getElementAt(i)
        interceptionFilterTitle = interceptionFilter.split(":")[0]
        if interceptionFilterTitle == "Scope items only":
            currentURL = URL(urlString)
            if not self._callbacks.isInScope(currentURL):
                message_passed_filters = False

        if interceptionFilterTitle == "URL Contains (simple string)":
            if interceptionFilter[30:] not in urlString:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Contains (regex)":
            regex_string = interceptionFilter[22:]

            if re.search(regex_string, urlString, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Not Contains (simple string)":
            if interceptionFilter[34:] in urlString:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Not Contains (regex)":
            regex_string = interceptionFilter[26:]
            if not re.search(regex_string, urlString, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body contains (simple string)":
            if interceptionFilter[40:] not in bodyStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body contains (regex)":
            regex_string = interceptionFilter[32:]
            if re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body NOT contains (simple string)":
            if interceptionFilter[44:] in bodyStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body Not contains (regex)":
            regex_string = interceptionFilter[36:]
            if not re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body contains (simple string)":
            if interceptionFilter[41:] not in resStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body contains (regex)":
            regex_string = interceptionFilter[33:]
            if re.search(regex_string, resStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body NOT contains (simple string)":
            if interceptionFilter[45:] in resStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body Not contains (regex)":
            regex_string = interceptionFilter[37:]
            if not re.search(regex_string, resStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Header contains":
            for header in list(resInfo.getHeaders()):
                if interceptionFilter[17:] in header:
                    message_passed_filters = False

        if interceptionFilterTitle == "Header doesn't contain":
            for header in list(resInfo.getHeaders()):
                if not interceptionFilter[17:] in header:
                    message_passed_filters = False

        if interceptionFilterTitle == "Only HTTP methods (newline separated)":
            filterMethods = interceptionFilter[39:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() not in filterMethods:
                message_passed_filters = False

        if interceptionFilterTitle == "Ignore HTTP methods (newline separated)":
            filterMethods = interceptionFilter[41:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() in filterMethods:
                message_passed_filters = False

        if interceptionFilterTitle == "Ignore OPTIONS requests":
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod == "OPTIONS":
                message_passed_filters = False

    return message_passed_filters


def handle_message(self, toolFlag, messageIsRequest, messageInfo):
    if tool_needs_to_be_ignored(self, toolFlag):
        return

    capture_last_cookie_header(self, messageInfo)
    capture_last_authorization_header(self, messageInfo)

    if (self.intercept and valid_tool(self, toolFlag)) or toolFlag == "AUTORIZEPRO":
        handle_304_status_code_prevention(self, messageIsRequest, messageInfo)

        if not messageIsRequest:
            if message_not_from_autorize(self, messageInfo):
                if self.ignore304.isSelected():
                    if isStatusCodesReturned(self, messageInfo, ["304", "204"]):
                        return
                if no_filters_defined(self):
                    checkAuthorization(self, messageInfo,
                                       self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),
                                       self.doUnauthorizedRequest.isSelected())
                else:
                    if message_passed_interception_filters(self, messageInfo):
                        checkAuthorization(self, messageInfo,
                                           self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),
                                           self.doUnauthorizedRequest.isSelected())


def send_request_to_autorize(self, messageInfo):
    if messageInfo.getResponse() is None:
        message = makeMessage(self, messageInfo, False, False)
        requestResponse = makeRequest(self, messageInfo, message)
        checkAuthorization(self, requestResponse,
                           self._helpers.analyzeResponse(requestResponse.getResponse()).getHeaders(),
                           self.doUnauthorizedRequest.isSelected())
    else:
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        httpService = messageInfo.getHttpService()
        newHttpRequestResponse = IHttpRequestResponseImplementation(httpService, request, response)
        newHttpRequestResponsePersisted = self._callbacks.saveBuffersToTempFiles(newHttpRequestResponse)
        checkAuthorization(self, newHttpRequestResponsePersisted,
                           self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),
                           self.doUnauthorizedRequest.isSelected())


def auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement):
    response = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(response)
    auth_enforced = False
    if andOrEnforcement == "And":
        andEnforcementCheck = True
        auth_enforced = True
    else:
        andEnforcementCheck = False
        auth_enforced = False

    for filter in filters:
        filter = self._helpers.bytesToString(bytes(filter))
        filter_kv = filter.split(":", 1)
        inverse = "NOT" in filter_kv[0]
        filter_kv[0] = filter_kv[0].replace(" NOT", "")
        filter = ":".join(filter_kv)

        if filter.startswith("Status code equals: "):
            statusCode = filter[20:]
            filterMatched = inverse ^ isStatusCodesReturned(self, requestResponse, statusCode)

        elif filter.startswith("Headers (simple string): "):
            filterMatched = inverse ^ (filter[25:] in self._helpers.bytesToString(
                requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()]))

        elif filter.startswith("Headers (regex): "):
            regex_string = filter[17:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(
                self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])))

        elif filter.startswith("Body (simple string): "):
            filterMatched = inverse ^ (filter[22:] in self._helpers.bytesToString(
                requestResponse.getResponse()[analyzedResponse.getBodyOffset():]))

        elif filter.startswith("Body (regex): "):
            regex_string = filter[14:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(
                p.search(self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])))

        elif filter.startswith("Full response (simple string): "):
            filterMatched = inverse ^ (filter[31:] in self._helpers.bytesToString(requestResponse.getResponse()))

        elif filter.startswith("Full response (regex): "):
            regex_string = filter[23:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse())))

        elif filter.startswith("Full response length: "):
            filterMatched = inverse ^ (str(len(response)) == filter[22:].strip())

        if andEnforcementCheck:
            if auth_enforced and not filterMatched:
                auth_enforced = False
        else:
            if not auth_enforced and filterMatched:
                auth_enforced = True

    return auth_enforced


def pre_check(self, oldStatusCode, newStatusCode, oldContent, newContent, modifyFlag):
    allowed_status_codes = {"200", "302", "301", "303", "307", "308"}
    statusCode = newStatusCode.split(" ")[1]
    if statusCode not in allowed_status_codes:
        # print(oriUrl, " ---> Status code not allowed: " + statusCode)
        return False
    if not modifyFlag:
        # print(oriUrl, " ---> Request not modified")
        return False
    if not detect_response_type(self, oldContent) or not detect_response_type(self, newContent):
        # print(oriUrl, " ---> Response content not API type")
        return False
    return True


def checkBypass(self, oriUrl, oriBody, oldStatusCode, newStatusCode, oldContent, newContent, filters, requestResponse,
                andOrEnforcement, isAuthorized):
    AI_res = ""
    if isAuthorized and self.apiKeyEnabledCheckbox.isSelected():
        if newStatusCode == oldStatusCode and 50 < len(oldContent) < 7000:
            apiKey = self.apiKeyField.getText()
            modelName = self.aiOptionComboBox.getSelectedItem()
            if apiKey:
                api_result_mapping = {
                    "true": self.BYPASSSED_STR,
                    "false": self.ENFORCED_STR,
                    "unknown": self.IS_ENFORCED_STR
                }
                AI_res = call_dashscope_api(self, apiKey, modelName, oriUrl, oriBody, oldContent, newContent)
                AI_res = api_result_mapping.get(AI_res, AI_res)
            else:
                self._callbacks.printError("API-Key is None")

    auth_enforced = False
    if filters:
        auth_enforced = auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement)

    if auth_enforced:
        return self.ENFORCED_STR, AI_res
    elif len(oldContent) == len(newContent):
        return self.BYPASSSED_STR, AI_res
    else:
        return self.IS_ENFORCED_STR, AI_res


def detect_response_type(self, content):
    try:
        content = content.strip()
        if content.startswith("{") and content.endswith("}"):
            return True
        elif content.startswith("<?xml"):
            return True
        else:
            return False
    except Exception:
        return False


def escape_special_characters(self, input_string):
    return input_string.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace(
        "\t", "")


def read_response(self, stream):
    reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
    response = StringBuilder()
    line = reader.readLine()
    while line is not None:
        response.append(line)
        line = reader.readLine()
    reader.close()
    return response.toString()


def extract_res_value(self, response_string):
    try:
        match = re.search(r'.*res\\":\\"(true|false|unknown)', response_string, re.DOTALL)
        if match:
            res_value = match.group(1)
            return res_value
        else:
            print("No 'res' field found in AI api response.")
            return ""
    except Exception as e:
        self._callbacks.printError("An error occurred while extracting 'res' field: " + str(e))
        return ""


def generate_prompt(self, modelName, system_prompt, user_prompt):
    return u"""
    {
        "model": "%s",
        "messages": [
            {
                "role": "system",
                "content": "%s"
            },
            {
                "role": "user", 
                "content": "%s"
            }
        ]
    }
        """ % (modelName, system_prompt, user_prompt)


def call_dashscope_api(self, apiKey, modelName, oriUrl, oriBody, res1, res2):
    if self.replaceQueryParam.isSelected():
        res_system_prompt = """**角色描述**：**角色描述**：你是一个判断是否存在越权的分析机器人，通过对比两个 HTTP 请求响应数据包的相似性，判断是否存在越权漏洞，并根据要求给出判断结果。
            **输入介绍**：用户提供了两个响应内容：
            - **响应 A**：账号 A 使用自己的 Cookie 请求自己资源接口返回的响应。
            - **响应 B**：账号 A 使用自己的 Cookie 请求他人资源接口返回的响应。

            **分析要求**：
            1. **对比响应内容**：
               - 忽略动态字段（如时间戳、traceID、会话 ID 等每次请求可能变化的字段）。
               - 重点对比响应 A 和 B 的 **非动态字段的结构和内容差异**。

            2. **判断依据**：
               - **越权成功（true）**：
                 - 若响应 A 和 B 的非动态字段结构完全一致，且 A 中有值的字段在 B 中有值或为null(因为b可能确实没数据，不代表越权失败)，内容不同但符合同类型数据规则，皆判定为越权成功。
                 - 若响应 B 包含响应 A 中业务数据对应的字段结构，但字段内容变为与他人资源有关（如他人资源的 ID、名称等）的值 或 字段内容值为null(因为b可能确实没数据，不代表越权失败)，皆判定为越权成功。。
                 - 若响应 A 和 B 中都存在 `success` 字段且值为 `true`，结构一致且响应内容较短无公开接口信息，则可能为操作接口成功，判定越权成功。
               - **越权失败（false）**：
                 - 若响应 B 明确返回错误信息（如“权限不足”、“资源不可访问”或 HTTP 状态码 403/401 等），判定为越权失败。
                 - 若响应 A 和 B 的非动态字段结构、字段值完全一致，判定越权失败。
                 - 若响应 A 和 B 的字段结构显著不同（如字段数量、层级、命名等差异），尤其是 B 的内容与 A 的响应中的类型明显不相关，判定为越权失败。
                 - 若响应 B 包含字段跟响应 A 中的业务字段完全无关，判定为越权失败。
               - **其他情况（unknown）**：
                 - 若响应 B 包含与资源 A 无关的业务数据字段和值，无法明确判断是否越权，则返回未知（unknown）。
                 - 若响应 A 和 B 的差异难以判断是否符合越权条件，则返回未知（unknown）。

            3. **输出格式**：
               - 返回 JSON 格式的结果：`res` 字段值为字符串格式，只能是 `'true'`、`'false'` 或 `'unknown'`。
               - 示例：`{"res":"true", "reason":"不超过50字的判断原因"}`。
               - `reason` 字段说明判断原因，不能超过 50 字。

            **注意事项**：
            1. 仅输出 JSON 格式的结果，不添加任何额外文本或解释。
            2. 确保 JSON 格式正确，以便于后续处理。
            3. 保持客观中立，仅根据提供的响应内容进行分析。

            **总体流程**：
            1. 接收并理解响应 A 和 B。
            2. 忽略动态字段，重点对比非动态字段的结构和内容差异。
            3. 逐步进行分析，严格按照前面的判断依据得出结论并输出指定 JSON 格式的结果。"""
        res_user_prompt = "Response A: %s, Response B: %s" % (res1, res2)
        request_body = generate_prompt(self, modelName, escape_special_characters(self, res_system_prompt),
                                       escape_special_characters(self, res_user_prompt))
        AI_res = request_dashscope_api(self, apiKey, modelName, oriUrl, request_body)
        return AI_res
    else:
        res_system_prompt = """**角色描述**：你是一个判断是否存在越权的分析机器人，通过对比两个 HTTP 请求响应数据包的相似性，判断是否存在越权漏洞，并根据要求给出判断结果。
            **输入介绍**：用户提供了两个响应内容:
            - **响应 A**：账号 A 的身份请求接口返回的响应。
            - **响应 B**：将账号 A 的 Cookie 替换为账号 B 的 Cookie 后重新请求获得的响应。

            **分析要求**：
            1. **对比响应内容**:
               - 重要！忽略动态字段（如时间戳、traceID、requestID 等每次请求可能变化的字段）,动态字段通常包括时间戳、会话 ID、trace ID、requestID 等字段。
               - 只对比响应 A 和 B 的非动态字段结构和内容，判断相似性。

            2. **判断依据**：
               - **越权成功（true）**：
                 - 若响应 B 的结构和内容与响应 A 完全一致(所有非动态字段)，判定为越权成功。
                 - 若响应 B 中包含响应 A 中的资源数据或账号数据，且非动态字段与 A 的内容高度一致，也判定为越权成功。
                 - 若响应 A 和 B 中都存在 `success` 字段且值为 `true`，结构一致且响应内容较短无公开信息，也判定越权成功。
               - **越权失败（false）**：
                 - 若响应 B 与响应 A 的结构和内容明显不同，尤其是结构不一致，判定为越权失败。
                 - 若响应 B 包含“权限不足”或“需要登录”等错误信息，判定为越权失败。
                 - 若响应 A 和 B 的结构一致，但账号特征字段（如用户名、邮箱、userid 等）中的值显示为账号 B 的信息而非账号 A 的信息，判定为越权失败。
               - **其他情况（unknown）**：
                 - 若响应 B 包含与账号 A 无关的业务数据或敏感数据，但无法明确判断是否越权，则返回未知（unknown）。
                 - 若响应 A 和 B 的差异难以判断为越权成功或失败，则返回未知（unknown）。

            3. **输出格式**：
               - 返回 JSON 格式的结果：`res` 字段值为字符串格式，只能是 `'true'`、`'false'` 或 `'unknown'`。
               - 示例：`{"res":"true", "reason":"不超过50字的判断原因"}`。
               - `reason` 字段说明判断原因，不能超过 50 字。

            **注意事项**：
            1. 仅输出 JSON 格式的结果，不添加任何额外文本或解释。
            2. 确保 JSON 格式正确，以便于后续处理。
            3. 保持客观中立，仅根据提供的响应内容进行分析。

            **总体流程**：
            1. 接收并理解响应 A 和 B。
            2. 忽略动态字段，重点对比非动态字段的结构和内容差异。
            3. 逐步的进行分析，得出结论输出指定 JSON 格式的结果。"""
        res1 = escape_special_characters(self, res1)
        res2 = escape_special_characters(self, res2)
        res_user_prompt = "Response A: %s, Response B: %s" % (res1, res2)
        request_body = generate_prompt(self, modelName, escape_special_characters(self, res_system_prompt),
                                       escape_special_characters(self, res_user_prompt))
        AI_res = request_dashscope_api(self, apiKey, modelName, oriUrl, request_body)
        return AI_res


def request_dashscope_api(self, api_key, modelName, orgUrl, request_body):
    try:
        url = URL("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions")
        if modelName.startswith("deepseek"):
            url = URL("https://api.deepseek.com/v1/chat/completions")
        elif modelName.startswith("gpt"):
            url = URL("https://api.openai.com/v1/chat/completions")
        elif modelName.startswith("glm"):
            url = URL("https://open.bigmodel.cn/api/paas/v4/chat/completions")
        elif modelName.startswith("hunyuan"):
            url = URL("https://api.hunyuan.cloud.tencent.com/v1/chat/completions")
        connection = url.openConnection()
        connection.setRequestMethod("POST")
        connection.setDoOutput(True)
        connection.setConnectTimeout(20000)
        connection.setReadTimeout(30000)

        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.setRequestProperty("Authorization", "Bearer " + api_key)

        # print("Request Body Before Encoding:\n" + request_body)

        outputStream = connection.getOutputStream()
        writer = OutputStreamWriter(outputStream, "UTF-8")
        writer.write(request_body)
        writer.flush()
        writer.close()
        outputStream.close()

        responseCode = connection.getResponseCode()

        if responseCode == HttpURLConnection.HTTP_OK or responseCode == HttpURLConnection.HTTP_CREATED:
            inputStream = connection.getInputStream()
            AI_res = read_response(self, inputStream)
            res_value = extract_res_value(self, AI_res)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            json_log = '{\n' \
                       '\t"timestamp": "%s",\n ' \
                       '\t"orig_url": "%s",\n ' \
                       '\t"ai_api_status": "%s",\n ' \
                       '\t"ai_analysis_result": "%s"\n ' \
                       '\t"ai_original_response": "%s"\n ' \
                       '}\n' % (
                           timestamp,
                           str(orgUrl),
                           str(responseCode),
                           str(res_value),
                           str(AI_res) if str(AI_res) else 'N/A'
                       )

            print(json_log)

            if res_value:
                return res_value
            return ""
        else:
            errorStream = connection.getErrorStream()
            if errorStream is not None:
                error_response = read_response(self, errorStream)
                print("Error Response :: " + error_response)
            else:
                print("POST request failed with response code " + str(responseCode))
            return ""
    except SSLHandshakeException:
        self._callbacks.printError(
            "SSL handshake failure: A secure connection cannot be established with the server. Please check your network Settings")
        return ""
    except EOFException:
        self._callbacks.printError(
            "The api connection was closed by the remote host. Please check your Internet connection.")
        return ""
    except Exception as e:
        self._callbacks.printError("An error occurred: " + str(e))
        return ""


def checkAuthorization(self, messageInfo, originalHeaders, checkUnauthorized):
    oriUrl, reqMethod, oriBody = getRequestBody(self, messageInfo)

    if checkUnauthorized:
        messageUnauthorized, _ = makeMessage(self, messageInfo, True, False)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        unauthorizedResponse = requestResponseUnauthorized.getResponse()
        analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
        statusCodeUnauthorized = analyzedResponseUnauthorized.getHeaders()[0]
        contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)

    message, modifyFlag = makeMessage(self, messageInfo, True, True)
    requestResponse = makeRequest(self, messageInfo, message)
    newResponse = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(newResponse)

    oldStatusCode = originalHeaders[0]
    newStatusCode = analyzedResponse.getHeaders()[0]
    oldContent = getResponseBody(self, messageInfo)
    newContent = getResponseBody(self, requestResponse)

    EDFilters = self.EDModel.toArray()

    if pre_check(self, oldStatusCode, newStatusCode, oldContent, newContent, modifyFlag):
        impression, AI_res = checkBypass(self, oriUrl, oriBody, oldStatusCode, newStatusCode, oldContent, newContent,
                                         EDFilters, requestResponse,
                                         self.AndOrType.getSelectedItem(), True)
    else:
        impression, AI_res = self.ENFORCED_STR, ""

    if checkUnauthorized:
        if pre_check(self, oldStatusCode, statusCodeUnauthorized, oldContent, contentUnauthorized, modifyFlag=True):
            EDFiltersUnauth = self.EDModelUnauth.toArray()
            impressionUnauthorized, _ = checkBypass(self, oriUrl, oriBody, oldStatusCode, statusCodeUnauthorized,
                                                    oldContent, contentUnauthorized,
                                                    EDFiltersUnauth, requestResponseUnauthorized,
                                                    self.AndOrTypeUnauth.getSelectedItem(), False)
        else:
            impressionUnauthorized = self.ENFORCED_STR

    self._lock.acquire()

    row = self._log.size()
    method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

    if checkUnauthorized:
        self._log.add(
            LogEntry(self.currentRequestNumber, self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                     self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression,
                     self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized), impressionUnauthorized,
                     AI_res))

    else:
        self._log.add(
            LogEntry(self.currentRequestNumber, self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                     self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression, None, "Disabled",
                     AI_res))

    SwingUtilities.invokeLater(UpdateTableEDT(self, "insert", row, row))
    self.currentRequestNumber += 1
    self._lock.release()


# 检查授权版本 2
def checkAuthorizationV2(self, messageInfo):
    checkAuthorization(self, messageInfo,
                       self._extender._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),
                       self._extender.doUnauthorizedRequest.isSelected())


def retestAllRequests(self):
    self.logTable.setAutoCreateRowSorter(True)
    for i in range(self.tableModel.getRowCount()):
        logEntry = self._log.get(self.logTable.convertRowIndexToModel(i))
        handle_message(self, "AUTORIZEPRO", False, logEntry._originalrequestResponse)
