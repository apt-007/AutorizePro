#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@File   : authorization.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   : Authorization module for AutorizePro
"""

import re
import json
import time
import hashlib
import datetime
import threading
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
from javax.net.ssl import SSLSocketFactory, SSLHandshakeException
from java.net import SocketException, EOFException
from javax.swing import SwingUtilities
from java.lang import StringBuilder

# Global variables
logged_html_urls = set()
logged_urls_lock = threading.Lock()
ai_analysis_cache = {}
cache_access_order = []
cache_lock = threading.Lock()
MAX_CACHE_SIZE = 1000

# Regex patterns
CODE_BLOCK_PATTERN = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL | re.IGNORECASE)
JSON_RES_PATTERN = re.compile(r'"res"\s*:\s*"([^"]*)"', re.IGNORECASE)
ESCAPED_JSON_RES_PATTERN = re.compile(r'\\"res\\"\s*:\s*\\"([^\\"]*)\\\"', re.IGNORECASE)
NESTED_RES_PATTERN = re.compile(r'[\"\']res[\"\']\s*:\s*[\"\'](\w+)[\"\']', re.IGNORECASE)
MARKDOWN_JSON_PATTERN = re.compile(r'```json\s*(\{.*?\})\s*```', re.DOTALL | re.IGNORECASE)
CHOICES_CONTENT_PATTERN = re.compile(r'"content":\s*".*?res.*?[\"\'](\w+)[\"\'].*?"', re.DOTALL | re.IGNORECASE)
HUNYUAN_PATTERN = re.compile(r'"content":\s*".*?res.*?[\'"](\w+)[\'"].*?"', re.DOTALL | re.IGNORECASE)
QIANWEN_PATTERN = re.compile(r'"text":\s*".*?res.*?[\'"](\w+)[\'"].*?"', re.DOTALL | re.IGNORECASE)
GLM_PATTERN = re.compile(r'"content":\s*".*?res.*?[\'"](\w+)[\'"].*?"', re.DOTALL | re.IGNORECASE)
GEMINI_PATTERN = re.compile(r'"text":\s*".*?res.*?[\'"](\w+)[\'"].*?"', re.DOTALL | re.IGNORECASE)
GEMINI_TEXT_PATTERN = re.compile(r'"text":\s*"((?:[^"\\\\]|\\\\.)*)"\s*}', re.DOTALL)
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)
HUNYUAN_CONTENT_PATTERN = re.compile(r'"content":\s*"((?:[^"\\\\]|\\\\.)*)"', re.DOTALL)
LOOSE_PATTERN = re.compile(r'(?:res|result|status)[\s\'":\[]*(?:true|false|success|fail)', re.IGNORECASE)


class LogEntry:
    def __init__(self, requestNumber, requestResponse, method, url, originalRequestResponse, authorization, unauthorizedRequestResponse, unauthorized, ai_analysis):
        self._requestNumber = requestNumber
        self._requestResponse = requestResponse
        self._method = method
        self._url = url
        self._originalrequestResponse = originalRequestResponse
        self._authorization = authorization
        self._unauthorizedRequestResponse = unauthorizedRequestResponse
        self._unauthorized = unauthorized
        self._ai_analysis = ai_analysis


class UpdateTableEDT(java.lang.Runnable):
    def __init__(self, extender, method, firstRow, lastRow):
        self._extender = extender
        self._method = method
        self._firstRow = firstRow
        self._lastRow = lastRow

    def run(self):
        if self._method == "insert":
            self._extender.tableModel.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._method == "update":
            self._extender.tableModel.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._method == "delete":
            self._extender.tableModel.fireTableRowsDeleted(self._firstRow, self._lastRow)


class IHttpRequestResponseImplementation:
    def __init__(self, httpService, request, response):
        self._httpService = httpService
        self._request = request
        self._response = response

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def getHttpService(self):
        return self._httpService

    def getComment(self):
        return None

    def getHighlight(self):
        return None

    def setComment(self, comment):
        pass

    def setHighlight(self, color):
        pass


def isStatusCodesReturned(self, requestResponse, statusCodes):
    if not requestResponse.getResponse():
        return False
    
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    statusCodeLine = analyzedResponse.getHeaders()[0]
    
    if isinstance(statusCodes, list):
        return any(str(code) in statusCodeLine for code in statusCodes)
    else:
        return str(statusCodes) in statusCodeLine


def getRequestBody(self, messageInfo):
    request = messageInfo.getRequest()
    analyzedRequest = self._helpers.analyzeRequest(request)
    return (
        str(analyzedRequest.getUrl()),
        str(analyzedRequest.getMethod()),
        self._helpers.bytesToString(request[analyzedRequest.getBodyOffset():])
    )


def getResponseBody(self, requestResponse):
    response = requestResponse.getResponse()
    if response is None:
        return ""
    
    analyzedResponse = self._helpers.analyzeResponse(response)
    return self._helpers.bytesToString(response[analyzedResponse.getBodyOffset():])


def makeRequest(self, messageInfo, message):
    httpService = messageInfo.getHttpService()
    return self._callbacks.makeHttpRequest(httpService, message)


def makeMessage(self, messageInfo, modified, removeOrNot):
    request = messageInfo.getRequest()
    analyzedRequest = self._helpers.analyzeRequest(request)
    headers = list(analyzedRequest.getHeaders())
    
    modifyFlag = False

    if modified:
        if removeOrNot:
            headers = [header for header in headers if not header.lower().startswith("authorization")]
            authorizationHeader = self.lastAuthorizationHeader.getText()
        else:
            replacementHeader = self.lastAuthorizationHeader.getText()
            for i, header in enumerate(headers):
                if header.lower().startswith("authorization"):
                    headers[i] = replacementHeader
                    break
            else:
                headers.append(replacementHeader)
            
            authorizationHeader = replacementHeader

        if authorizationHeader and authorizationHeader.strip():
            modifyFlag = True

    requestBody = request[analyzedRequest.getBodyOffset():]
    return self._helpers.buildHttpMessage(headers, requestBody), modifyFlag


def tool_needs_to_be_ignored(self, toolFlag):
    return toolFlag == self._callbacks.TOOL_PROXY and not self.intercept


def valid_tool(self, toolFlag):
    return toolFlag in [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_TARGET, 
                       self._callbacks.TOOL_REPEATER, self._callbacks.TOOL_INTRUDER,
                       self._callbacks.TOOL_SCANNER, self._callbacks.TOOL_SEQUENCER,
                       self._callbacks.TOOL_EXTENDER]


def capture_last_cookie_header(self, messageInfo):
    if messageInfo.getRequest():
        analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
        for header in analyzedRequest.getHeaders():
            if header.lower().startswith("cookie"):
                self.lastCookieHeader.setText(header)
                break


def capture_last_authorization_header(self, messageInfo):
    if messageInfo.getRequest():
        analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
        for header in analyzedRequest.getHeaders():
            if header.lower().startswith("authorization"):
                self.lastAuthorizationHeader.setText(header)
                break


def handle_304_status_code_prevention(self, messageIsRequest, messageInfo):
    if not messageIsRequest and self.prevent304.isSelected():
        request = messageInfo.getRequest()
        if request:
            requestString = self._helpers.bytesToString(request)
            
            # Remove cache-related headers
            headers_to_remove = [
                "if-modified-since", "if-none-match", "if-match",
                "if-unmodified-since", "if-range", "cache-control"
            ]
            
            lines = requestString.split('\n')
            filtered_lines = []
            
            for line in lines:
                header_name = line.split(':', 1)[0].lower().strip()
                if header_name not in headers_to_remove:
                    filtered_lines.append(line)
            
            modifiedRequest = '\n'.join(filtered_lines)
            messageInfo.setRequest(self._helpers.stringToBytes(modifiedRequest))


def message_not_from_autorize(self, messageInfo):
    httpService = messageInfo.getHttpService()
    if not httpService:
        return True
    
    host = httpService.getHost()
    port = httpService.getPort()
    protocol = httpService.getProtocol()
    
    return not (host == "127.0.0.1" and port == 8080 and protocol == "http")


def no_filters_defined(self):
    return self.IFModel.getRowCount() == 0


def message_passed_interception_filters(self, messageInfo):
    message_passed_filters = True
    
    for filter_index in range(self.IFModel.getRowCount()):
        rule_matched = True
        interceptionFilterTitle = self.IFModel.getValueAt(filter_index, 0)
        filter_content = self.IFModel.getValueAt(filter_index, 1)
        
        if interceptionFilterTitle == "URL Contains (simple string)":
            url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
            if filter_content not in url:
                rule_matched = False

        elif interceptionFilterTitle == "URL Contains (regex)":
            url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
            try:
                if not re.search(filter_content, url):
                    rule_matched = False
            except:
                rule_matched = False

        elif interceptionFilterTitle == "Only HTTP methods (newline separated)":
            filterMethods = filter_content.split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() not in filterMethods:
                rule_matched = False

        elif interceptionFilterTitle == "Ignore HTTP methods (newline separated)":
            filterMethods = filter_content.split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() in filterMethods:
                rule_matched = False

        elif interceptionFilterTitle == "Ignore OPTIONS requests":
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod == "OPTIONS":
                rule_matched = False
        
        if not rule_matched:
            message_passed_filters = False
            break
    
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


def escape_special_characters(self, input_string):
    return input_string.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace(
        "\t", "")


def extract_gemini_text(self, response_string):
    try:
        import json as json_module
        parsed = json_module.loads(response_string)
        
        if 'candidates' in parsed:
            for candidate in parsed['candidates']:
                if 'content' in candidate:
                    content = candidate['content']
                    if 'parts' in content:
                        for part in content['parts']:
                            if 'text' in part:
                                return part['text']
        return None
    except Exception as e:
        return None


def generate_prompt(self, modelName, system_prompt, user_prompt):
    if modelName.lower().startswith("gemini"):
        return u"""
        {
            "contents": [
                {
                    "parts": [
                        {
                            "text": "%s\\n\\n%s"
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 1024
            }
        }
        """ % (system_prompt, user_prompt)
    else:
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


def extract_res_value(self, response_string):
    try:
        if not response_string or response_string.strip() == "":
            return ""
            
        code_block_match = CODE_BLOCK_PATTERN.search(response_string)
        if code_block_match:
            content_to_process = code_block_match.group(1).strip()
            res_in_block = RES_FIELD_PATTERN.search(content_to_process)
            if res_in_block:
                print("Complete AI Analysis: " + content_to_process)
                return res_in_block.group(1).lower()
        else:
            content_to_process = response_string
        
        patterns = [
            JSON_RES_PATTERN,
            ESCAPED_JSON_RES_PATTERN,
            NESTED_RES_PATTERN,
            MARKDOWN_JSON_PATTERN,
            CHOICES_CONTENT_PATTERN,
            HUNYUAN_PATTERN,
            QIANWEN_PATTERN,
            GLM_PATTERN,
            GEMINI_PATTERN
        ]
        
        for pattern in patterns:
            match = pattern.search(content_to_process)
            if match:
                return match.group(1).lower()
        
        # Special handling for Gemini responses
        if "candidates" in content_to_process:
            text_content = extract_gemini_text(self, content_to_process)
            if text_content:
                text_content = text_content.replace('\\n', '\n').replace('\\\"', '\"').replace('\\\\', '\\')
                res_in_text = RES_FIELD_PATTERN.search(text_content)
                if res_in_text:
                    print("Complete AI Analysis (Gemini): " + text_content)
                    return res_in_text.group(1).lower()
                try:
                    if '{' in text_content and '}' in text_content:
                        json_start = text_content.find('{')
                        json_end = text_content.rfind('}') + 1
                        json_str = text_content[json_start:json_end]
                        parsed = json.loads(json_str)
                        if 'res' in parsed:
                            print("Complete AI Analysis (Gemini JSON): " + json_str)
                            return str(parsed['res']).lower()
                except:
                    pass
        
        return ""
    except Exception as e:
        print("Error in extract_res_value: " + str(e))
        return ""


def read_response(self, stream):
    reader = None
    try:
        try:
            reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
            response = StringBuilder()
            
            line = reader.readLine()
            while line is not None:
                response.append(line)
                response.append("\n")
                line = reader.readLine()
            
            return response.toString()
        except Exception as e:
            for encoding in ["UTF-8-SIG", "ISO-8859-1", "GBK", "GB2312", "GB18030"]:
                try:
                    if reader is not None:
                        reader.close()
                    reader = BufferedReader(InputStreamReader(stream, encoding))
                    response = StringBuilder()
                    
                    line = reader.readLine()
                    while line is not None:
                        response.append(line)
                        response.append("\n")
                        line = reader.readLine()
                    
                    return response.toString()
                except Exception as e2:
                    continue
            
            return ""
    except Exception as e:
        return ""
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception as e:
                pass


def request_dashscope_api(self, api_key, modelName, orgUrl, request_body):
    max_retries = 3
    retry_count = 0
    retry_delay = 2
    
    api_endpoints = {
        "deepseek": "https://api.deepseek.com/v1/chat/completions",
        "gpt": "https://api.openai.com/v1/chat/completions",
        "glm": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "hunyuan": "https://api.hunyuan.cloud.tencent.com/v1/chat/completions",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "default": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    }
    
    api_url = api_endpoints["default"]
    for prefix, endpoint in api_endpoints.items():
        if modelName.lower().startswith(prefix):
            api_url = endpoint
            if prefix == "gemini":
                api_url = endpoint.format(model=modelName)
            break
    
    while retry_count < max_retries:
        connection = None
        outputStream = None
        writer = None
        inputStream = None
        errorStream = None
        
        try:
            if retry_count > 0:
                time.sleep(retry_delay * (2 ** (retry_count - 1)))
                
            url = URL(api_url)
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setDoOutput(True)
            connection.setConnectTimeout(30000)
            connection.setReadTimeout(60000)

            if hasattr(connection, 'setSSLSocketFactory'):
                connection.setSSLSocketFactory(SSLSocketFactory.getDefault())
                connection.setHostnameVerifier(lambda hostname, session: True)

            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            
            if modelName.lower().startswith("gemini"):
                connection.setRequestProperty("X-goog-api-key", api_key)
            else:
                connection.setRequestProperty("Authorization", "Bearer " + api_key)
            
            if modelName.lower().startswith("glm"):
                connection.setRequestProperty("User-Agent", "AutorizePro/1.0")
            
            outputStream = connection.getOutputStream()
            writer = OutputStreamWriter(outputStream, "UTF-8")
            writer.write(request_body)
            writer.flush()

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
                           '}\n' % (
                               timestamp,
                               str(orgUrl),
                               str(responseCode),
                               str(res_value)
                           )

                print(json_log)
                
                if res_value:
                    return res_value
                return ""
            else:
                retry_count += 1
                if retry_count == max_retries:
                    return ""
                continue
                
        except (SSLHandshakeException, EOFException, SocketException):
            retry_count += 1
            if retry_count == max_retries:
                return ""
            continue
            
        except Exception as e:
            retry_count += 1
            if retry_count == max_retries:
                return ""
            continue
        finally:
            resources = [writer, outputStream, inputStream, errorStream]
            for resource in resources:
                if resource is not None:
                    try:
                        resource.close()
                    except Exception as e:
                        pass
            
    return ""


def call_dashscope_api(self, apiKey, modelName, oriUrl, oriBody, res1, res2):
    if apiKey is None:
        return "unknown"

    res_system_prompt = """Role Description: You are an authorization vulnerability detection robot that determines whether privilege escalation vulnerabilities exist by comparing the similarity of two HTTP response data packets and provides judgment results according to requirements.
        Input Description: The user provided two response contents:
        - Response A: The response returned when account A's identity requests the interface.
        - Response B: The response obtained after replacing account A's Cookie with account B's Cookie and re-requesting.

        Analysis Requirements:
        1. Compare response content:
           - Important! Ignore dynamic fields (such as timestamps, traceID, requestID and other fields that may change with each request). Dynamic fields usually include timestamps, session IDs, trace IDs, requestIDs and other fields.
           - Only compare the non-dynamic field structures and contents of responses A and B to determine similarity.

        2. Judgment criteria:
           - Privilege escalation successful (true):
             - If the structure and content of response B are completely consistent with response A (all non-dynamic fields), it is determined that privilege escalation is successful.
             - If response B contains resource data or account data from response A, and the non-dynamic fields are highly consistent with the content of A, it is also determined that privilege escalation is successful.
             - If both responses A and B contain a `success` field with a value of `true`, have consistent structures and short response content without public information, privilege escalation is also determined to be successful.
           - Privilege escalation failed (false):
             - If the structure and content of response B are obviously different from response A, especially if the structures are inconsistent, it is determined that privilege escalation failed.
             - If response B contains error information such as "insufficient permissions" or "login required", it is determined that privilege escalation failed.
             - If the structures of responses A and B are consistent, but the account characteristic fields (such as username, email, userid, etc.) show account B's information instead of account A's information, it is determined that privilege escalation failed.
           - Other situations (unknown):
             - If response B contains business data or sensitive data unrelated to account A, but it cannot be clearly determined whether privilege escalation occurs, return unknown.
             - If the differences between responses A and B are difficult to determine as privilege escalation success or failure, return unknown.

        3. Output format:
           - Return results in JSON format: the `res` field value is in string format and can only be `'true'`, `'false'` or `'unknown'`.
           - Example: `{"res":"true", "reason":"Judgment reason not exceeding 50 characters"}`.
           - The `reason` field explains the judgment reason and cannot exceed 50 characters.

        Notes:
        1. Only output results in JSON format, do not add any additional text or explanations.
        2. Ensure the JSON format is correct for subsequent processing.
        3. Stay objective and neutral, and only analyze based on the provided response content.

        Overall process:
        1. Receive and understand responses A and B.
        2. Ignore dynamic fields and focus on comparing the structural and content differences of non-dynamic fields.
        3. Conduct step-by-step analysis to reach conclusions and output specified JSON format results."""
    
    res1 = escape_special_characters(self, res1)
    res2 = escape_special_characters(self, res2)
    res_user_prompt = "Response A: %s, Response B: %s" % (res1, res2)
    request_body = generate_prompt(self, modelName, escape_special_characters(self, res_system_prompt),
                                   escape_special_characters(self, res_user_prompt))
    AI_res = request_dashscope_api(self, apiKey, modelName, oriUrl, request_body)
    return AI_res


def checkBypass(self, oriUrl, oriBody, oldStatusCode, newStatusCode, oldContent, newContent, filters, requestResponse,
                andOrEnforcement, isAuthorized):
    AI_res = ""
    if isAuthorized and hasattr(self, 'apiKeyEnabledCheckbox') and self.apiKeyEnabledCheckbox.isSelected():
        if newStatusCode == oldStatusCode and 50 < len(oldContent) < 7000:
            apiKey = getattr(self, 'apiKeyField', None)
            if apiKey:
                apiKey = apiKey.getText()
            
            modelName = getattr(self, 'aiModelTextField', None)
            if modelName:
                modelName = modelName.getText()
            else:
                modelName = None
                    
            if apiKey and modelName:
                AI_result = call_dashscope_api(self, apiKey, modelName, oriUrl, oriBody, oldContent, newContent)
                api_result_mapping = {
                    "true": getattr(self, 'BYPASSSED_STR', "Bypassed"),
                    "false": getattr(self, 'ENFORCED_STR', "Enforced"),
                    "unknown": getattr(self, 'IS_ENFORCED_STR', "Is Enforced?")
                }
                AI_res = api_result_mapping.get(AI_result, AI_result)

    if len(oldContent) == len(newContent):
        return getattr(self, 'BYPASSSED_STR', "Bypassed"), AI_res
    else:
        return getattr(self, 'IS_ENFORCED_STR', "Is Enforced?"), AI_res


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

    if modifyFlag:
        impression, AI_res = checkBypass(self, oriUrl, oriBody, oldStatusCode, newStatusCode, oldContent, newContent,
                                         None, requestResponse, "Or", True)
    else:
        impression, AI_res = getattr(self, 'ENFORCED_STR', "Enforced"), ""

    if checkUnauthorized:
        impressionUnauthorized, _ = checkBypass(self, oriUrl, oriBody, oldStatusCode, statusCodeUnauthorized,
                                                oldContent, contentUnauthorized, None, requestResponseUnauthorized,
                                                "Or", False)
    else:
        impressionUnauthorized = "Disabled"

    # Add to log
    if hasattr(self, '_lock'):
        self._lock.acquire()
        try:
            row = self._log.size()
            method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

            if checkUnauthorized:
                self._log.add(
                    LogEntry(getattr(self, 'currentRequestNumber', 0), 
                             self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                             self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression,
                             self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized), impressionUnauthorized,
                             AI_res))
            else:
                self._log.add(
                    LogEntry(getattr(self, 'currentRequestNumber', 0), 
                             self._callbacks.saveBuffersToTempFiles(requestResponse), method,
                             self._helpers.analyzeRequest(requestResponse).getUrl(), messageInfo, impression, None, "Disabled",
                             AI_res))

            SwingUtilities.invokeLater(UpdateTableEDT(self, "insert", row, row))
            if hasattr(self, 'currentRequestNumber'):
                self.currentRequestNumber += 1
        finally:
            self._lock.release()
