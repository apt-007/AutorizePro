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
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from java.lang import StringBuilder
from javax.swing import SwingUtilities

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
        inverse = "NOT" in filter
        filter = filter.replace(" NOT", "")

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


def is_json_response(self, content):
    try:
        content = content.strip()
        if content.startswith("{") and content.endswith("}") and len(content) > 2:
            return True
        return False
    except:
        return False


def checkBypass(self, oldStatusCode, newStatusCode, oldContent, newContent, filters, requestResponse, andOrEnforcement, isAuthorized):
    AI_res = ""
    if oldStatusCode == newStatusCode:
        auth_enforced = 0

        if isAuthorized and self.apiKeyEnabledCheckbox.isSelected():
            if is_json_response(self, oldContent) and is_json_response(self, newContent) and 100 < len(oldContent) < 3000:
                api_key = self.apiKeyField.getText()
                if api_key:
                    AI_res = call_dashscope_api(self, api_key, oldContent, newContent)
                    if AI_res == "true":
                        AI_res = self.BYPASSSED_STR
                    elif AI_res == "false":
                        AI_res = self.ENFORCED_STR
                    elif AI_res == "unknown":
                        AI_res = self.IS_ENFORCED_STR
                else:
                    self._callbacks.printError("API-Key is None")

        if len(filters) > 0:
            auth_enforced = auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement)

        if auth_enforced:
            return self.ENFORCED_STR, AI_res

        elif oldContent == newContent:
            return self.BYPASSSED_STR, AI_res

        else:
            return self.IS_ENFORCED_STR, AI_res
    else:
        return self.ENFORCED_STR, AI_res


def escape_special_characters(self, input_string):
    return input_string.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "")


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
            print("No 'res' field found in response.")
            return ""
    except Exception as e:
        self._callbacks.printError("An error occurred while extracting 'res' field: " + str(e))
        return ""


def call_dashscope_api(self, api_key, res1, res2):
    try:
        url = URL("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions")
        connection = url.openConnection()
        connection.setRequestMethod("POST")
        connection.setDoOutput(True)
        connection.setConnectTimeout(20000)
        connection.setReadTimeout(30000)

        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.setRequestProperty("Authorization", "Bearer " + api_key)

        res1_escaped = escape_special_characters(self, res1)
        res2_escaped = escape_special_characters(self, res2)
        system_message = escape_special_characters(self,
            # "角色描述: 你是一个通过对比两个http请求响应数据包相似性判断是否越权的机器人，需要结合下面的要求以及你自己的知识给出最佳的判断结果。 \n\n输入介绍: 用户提供的响应A内容为账号A的去请求某接口的响应, 响应B为将请求中A账号的Cookie替换为账号B的Cookie之后重放该请求获取到的响应。\n分析要求: \n1. 对比响应内容：首先比较响应 A 和响应 B 的结构和内容，忽略动态字段（如时间戳、随机数、会话 ID 等可能每次请求都会变化的字段），响应 B 跟 响应 A 的结构以及内容相似度是否很高。\n2. 判断结果：a.如果响应 B 与响应 A 的结构和非动态字段内容都非常相似，判定为越权成功。b.如果响应B中包含了账号A的数据，判定为越权成功。c.如果响应B结构和内容均与响应A不相似，判定越权失败。d.如果响应B中存在权限不足等权限控制返回的错误信息，判定为越权失败。e.如果响应A和B的内容均为公开数据 或 两个响应大部分相同字段的具体值不同,存在不同账号特征 或 除动态字段外的字段均无实际值(比如值为null),则判定越权失败。f.其他情况结合你对越权知识的了解自主判断是否越权，当无法确定是否越权时，判定为未知。\n输出格式：\n仅以 JSON 格式返回结果，格式示例：\n{\"res\":\"true\", \"reaso\": \"不超过20字的判断原因\"}'\n res 字段值为字符串格式，只能是 'true'、'false' 或 'unknown' 中的一个值。\n  reason 字段给出判断的原因，不能超过20字。\n\n注意事项：\n1.输出仅包含 JSON 结果，不要添加任何额外的文本或解释。\n2.确保 JSON 格式正确，无语法错误，便于后续处理。\n3.保持客观中立,仅根据提供的响应内容进行分析。\n\n总体流程：\n1.接收响应A和响应B并理解 \n2. 进行分析：按照分析要求，对响应A和B进行比较,忽略动态字段，重点关注结构和非动态字段的差异。\n3. 输出结果：根据分析得出的结论，按照指定的 JSON 格式输出结果。\n谨记必须按照我给出的分析要求结合越权知识进行分析。"
            "角色描述: 你是一个通过对比两个http请求响应数据包相似性判断是否越权的机器人，需要结合下面的要求以及你自己的知识给出最佳的判断结果。 \n\n输入介绍: 用户提供的响应A内容为账号A身份的去请求某接口的响应, 响应B为将请求中A账号的Cookie替换为账号B的Cookie之后重放该请求获取到的响应。\n分析要求: \n1. 对比响应内容：忽略动态字段（如时间戳、随机数、会话 ID 等可能每次请求都会变化的字段），然后比较响应 A 和响应 B 的结构和内容相似度。\n2. 判断依据参考如下: \n越权失败: a.如果响应B结构和内容均与响应A不相似，判定越权失败。b.如果响应B中存在权限不足、需要登录等权限控制返回的错误信息，判定为越权失败。c.如果响应A和B的内容均为公开接口返回的数据(如接口说明) 或 除动态字段（如时间戳、随机数、会话 ID 等可能每次请求都会变化的字段）之外的字段值大部分均为 null， 则判定越权失败。d.如果两个响应的结构相同，但账号特征字段(账号用户名、邮箱、id)值不同,则判定越权失败。\n越权成功: \na.如果响应 B 与响应 A 的响应结构相似 且 非动态字段内容不为空 且 非动态字段值都非常相似，判定为越权成功。b.如果响应B中包含了账号A的个人业务数据、账号数据，判定为越权成功。c.如果响应A和响应B中存在success字段且值都为true,则判定越权成功。\n其他情况:a.其他情况结合你对越权知识的了解自主判断是否越权，当无法确定是否越权时，判定为未知。\n输出格式：\n仅以 JSON 格式返回结果，格式示例：\n{\"res\":\"true\", \"reaso\": \"不超过20字的判断原因\"}'\n res 字段值为字符串格式，只能是 'true'、'false' 或 'unknown' 中的一个值。\n  reason 字段给出判断的原因，不能超过30字。\n\n注意事项：\n1.输出仅包含 JSON 结果，不要添加任何额外的文本或解释。\n2.确保 JSON 格式正确，无语法错误，便于后续处理。\n3.保持客观中立,仅根据提供的响应内容进行分析。\n\n总体流程：\n1.接收响应A和响应B并理解 \n2. 进行分析：按照分析要求，对响应A和B进行比较,忽略动态字段，重点关注结构和非动态字段的差异。\n3. 输出结果：根据分析得出的结论，按照指定的 JSON 格式输出结果。\n谨记必须按照我给出的分析要求结合越权知识进行分析。"
        )

        request_body = u"""
        {
            "model": "qwen-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "%s"
                },
                {
                    "role": "user", 
                    "content": "账号A请求接口返回的响应A: %s, 替换为账号B的cookie后重放请求获取的响应B: %s"
                }
            ]
        }
        """ % (system_message, res1_escaped, res2_escaped)

        # print("Request Body Before Encoding:\n" + request_body)

        outputStream = connection.getOutputStream()
        writer = OutputStreamWriter(outputStream, "UTF-8")
        writer.write(request_body)
        writer.flush()
        writer.close()
        outputStream.close()

        responseCode = connection.getResponseCode()
        # print("AI API Response.Code :: " + str(responseCode))

        if responseCode == HttpURLConnection.HTTP_OK or responseCode == HttpURLConnection.HTTP_CREATED:
            inputStream = connection.getInputStream()
            AI_res = read_response(self, inputStream)
            # print("AI API Response.Body :: " + AI_res)

            res_value = extract_res_value(self, AI_res)
            # print("---> The result of AI judgment :: " + res_value)
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

    except Exception as e:
        self._callbacks.printError("An error occurred: " + str(e))
        return ""


def checkAuthorization(self, messageInfo, originalHeaders, checkUnauthorized):
    if checkUnauthorized:
        messageUnauthorized = makeMessage(self, messageInfo, True, False)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        unauthorizedResponse = requestResponseUnauthorized.getResponse()
        analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
        statusCodeUnauthorized = analyzedResponseUnauthorized.getHeaders()[0]
        contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)

    message = makeMessage(self, messageInfo, True, True)
    requestResponse = makeRequest(self, messageInfo, message)
    newResponse = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(newResponse)

    oldStatusCode = originalHeaders[0]
    newStatusCode = analyzedResponse.getHeaders()[0]
    oldContent = getResponseBody(self, messageInfo)
    newContent = getResponseBody(self, requestResponse)

    EDFilters = self.EDModel.toArray()

    impression, AI_res = checkBypass(self, oldStatusCode, newStatusCode, oldContent, newContent, EDFilters, requestResponse,
                             self.AndOrType.getSelectedItem(), True)
    if checkUnauthorized:
        EDFiltersUnauth = self.EDModelUnauth.toArray()
        impressionUnauthorized, _ = checkBypass(self, oldStatusCode, statusCodeUnauthorized, oldContent,
                                             contentUnauthorized, EDFiltersUnauth, requestResponseUnauthorized,
                                             self.AndOrTypeUnauth.getSelectedItem(), False)

    self._lock.acquire()

    row = self._log.size()
    method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

    if checkUnauthorized:
        self._log.add(
            LogEntry(self.currentRequestNumber, self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                     self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression,
                     self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized), impressionUnauthorized, AI_res))

    else:
        self._log.add(
            LogEntry(self.currentRequestNumber, self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                     self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression, None, "Disabled", AI_res))

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
