#!/usr/bin/env python3
# coding: utf-8

"""
@File   : http.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   : 该模块包含处理 HTTP 请求和响应的各种辅助函数，包括构建请求、提取头部和内容等功能，并定义了自定义的 HttpRequestResponse 实现。
"""

import array
import re
from burp import IHttpRequestResponse


def isStatusCodesReturned(self, messageInfo, statusCodes):
    firstHeader = self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders()[0]
    if type(statusCodes) == list:
        for statusCode in statusCodes:
            if statusCode in firstHeader:
                return True
    elif type(statusCodes) == str or type(statusCodes) == unicode:
        if statusCodes in firstHeader:
            return True
    return False


def makeRequest(self, messageInfo, message):
    requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
    httpService = self._helpers.buildHttpService(
        str(requestURL.getHost()),
        int(requestURL.getPort()),
        requestURL.getProtocol() == "https"
    )
    return self._callbacks.makeHttpRequest(httpService, message)


def makeMessage(self, messageInfo, removeOrNot, authorizeOrNot):
    requestInfo = self._helpers.analyzeRequest(messageInfo)
    headers = requestInfo.getHeaders()
    modifiedFlag = False

    if removeOrNot:
        headers = list(headers)
        queryFlag = self.replaceQueryParam.isSelected()

        if queryFlag:
            requestLine = headers[0]
            replaceParams = self.replaceString.getText().splitlines()

            method, url, protocol = requestLine.split(" ", 2)
            path_and_query = url.split("?", 1)
            path = path_and_query[0]
            query = path_and_query[1] if len(path_and_query) > 1 else ""
            if authorizeOrNot:
                for param in replaceParams:
                    if '=' in param:
                        if param.startswith("path:"):
                            paramKey, paramValue = param[5:].split('=', 1)
                            paramKey = paramKey.strip()
                            paramValue = paramValue.strip()
                            pattern = r'(?<!\w){}(?!\w)'.format(re.escape(paramKey))
                            newPath = re.sub(pattern, paramValue, path)
                            if newPath != path:
                                modifiedFlag = True
                                path = newPath
                        else:
                            paramKey, paramValue = param.split('=', 1)
                            paramKey = paramKey.strip()
                            paramValue = paramValue.strip()
                            pattern = r'([?&]){}=[^&\s]*'.format(re.escape(paramKey))
                            replacement = r'\1{}={}'.format(paramKey, paramValue)
                            newQuery = re.sub(pattern, replacement, query, count=0, flags=re.DOTALL)
                            if newQuery != query:
                                modifiedFlag = True
                                query = newQuery
                    else:
                        print("Skipping invalid replacement rule: '{}'".format(param))
                        continue

                if query:
                    new_url = "{}?{}".format(path, query)
                else:
                    new_url = path
                headers[0] = "{} {} {}".format(method, new_url, protocol)
            else:
                for header in headers[1:]:
                    if header.lower().startswith(("cookie:", "authorization:", "token")):
                        headers.remove(header)
        else:
            removeHeadersStr = self.replaceString.getText()
            if authorizeOrNot:
                removeHeaders = [header for header in removeHeadersStr.split() if header.endswith(':')]
            else:
                removeHeaders = [header.strip() for header in removeHeadersStr.split() if header if header.lower().startswith(("cookie:", "authorization:", "token"))]
            for header in headers[1:]:
                for removeHeader in removeHeaders:
                    if header.lower().startswith(removeHeader.lower()):
                        headers.remove(header)

        if authorizeOrNot:
            for k, v in self.badProgrammerMRModel.items():
                if v["type"] == "Headers (simple string):":
                    modifiedHeaders = map(lambda h: h.replace(v["match"], v["replace"]), headers[1:])
                    headers = [headers[0]] + modifiedHeaders
                    if newHeaders != headers:
                        modifiedFlag = True
                    headers = newHeaders
                if v["type"] == "Headers (regex):":
                    modifiedHeaders = map(lambda h: re.sub(v["regexMatch"], v["replace"], h), headers[1:])
                    headers = [headers[0]] + modifiedHeaders
                    if newHeaders != headers:
                        modifiedFlag = True
                    headers = newHeaders

            if not queryFlag:
                replaceStringLines = self.replaceString.getText().splitlines()
                for h in replaceStringLines:
                    if h:
                        headers.append(h)
                        modifiedFlag = True

    msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]

    if authorizeOrNot and msgBody is not None:
        msgBody = self._helpers.bytesToString(msgBody)
        for k, v in self.badProgrammerMRModel.items():
            if v["type"] == "Body (simple string):":
                newBody = msgBody.replace(v["match"], v["replace"])
                if newBody != msgBody:
                    modifiedFlag = True
                msgBody = newBody
            if v["type"] == "Body (regex):":
                newBody = re.sub(v["regexMatch"], v["replace"], msgBody)
                if newBody != msgBody:
                    modifiedFlag = True
                msgBody = newBody
        msgBody = self._helpers.stringToBytes(msgBody)

    newMessage = self._helpers.buildHttpMessage(headers, msgBody)

    return newMessage, modifiedFlag


def getRequestBody(self, messageInfo):
    httpService = messageInfo.getHttpService()

    request = messageInfo.getRequest()
    requestInfo = self._helpers.analyzeRequest(httpService, request)

    full_url = requestInfo.getUrl()
    request_method = requestInfo.getMethod()
    body_offset = requestInfo.getBodyOffset()
    request_body = self._helpers.bytesToString(request[body_offset:])

    return full_url, request_method, request_body


def getResponseHeaders(self, requestResponse):
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    return self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])


#  (!!!)  获取响应体的旧版本函数，暂时保留，观察新函数使用反馈
# def getResponseBody(self, requestResponse):
#     analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
#     return self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])

def getResponseBody(self, requestResponse):
    """
    提取 HTTP 响应体，并确保正确解码文本内容，同时支持处理非 UTF-8 字节数据和二进制内容。
    """
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    headers = analyzedResponse.getHeaders()
    charset = "UTF-8"

    for header in headers:
        if header.lower().startswith("content-type:"):
            if "charset=" in header.lower():
                charset = header.lower().split("charset=")[-1].strip().strip(";")
                break

    body_bytes = requestResponse.getResponse()[analyzedResponse.getBodyOffset():]
    if isinstance(body_bytes, array.array):
        body_bytes = body_bytes.tostring()

    if any(header.lower().startswith("content-type:") and
           ("image" in header.lower() or "application/octet-stream" in header.lower())
           for header in headers):
        return body_bytes

    try:
        return body_bytes.decode(charset)
    except (UnicodeDecodeError, LookupError) as e:
        self._callbacks.printError("Error decoding response body with charset %s: %s" % (charset, str(e)))
        try:
            return body_bytes.decode("utf-8-sig")
        except (UnicodeDecodeError, LookupError):
            try:
                return body_bytes.decode("ISO-8859-1")
            except (UnicodeDecodeError, LookupError):
                return body_bytes.decode("UTF-8", errors="replace")
    except Exception as e:
        self._callbacks.printError("Unexpected error decoding response body: %s" % str(e))
        return body_bytes.decode("UTF-8", errors="replace")


def getResponseContentLength(self, response):
    return len(response) - self._helpers.analyzeResponse(response).getBodyOffset()


def get_cookie_header_from_message(self, messageInfo):
    headers = list(self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders())
    for header in headers:
        if header.strip().lower().startswith("cookie:"):
            return header
    return None


def get_authorization_header_from_message(self, messageInfo):
    headers = list(self._helpers.analyzeRequest(messageInfo.getRequest()).getHeaders())
    for header in headers:
        if header.strip().lower().startswith("authorization:"):
            return header
    return None


class IHttpRequestResponseImplementation(IHttpRequestResponse):
    def __init__(self, service, req, res):
        self._httpService = service
        self._request = req
        self._response = res
        self._comment = None
        self._highlight = None

    def getComment(self):
        return self._comment

    def getHighlight(self):
        return self._highlight

    def getHttpService(self):
        return self._httpService

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, c):
        self._comment = c

    def setHighlight(self, h):
        self._highlight = h

    def setHttpService(self, service):
        self._httpService = service

    def setRequest(self, req):
        self._request = req

    def setResponse(self, res):
        self._response = res
