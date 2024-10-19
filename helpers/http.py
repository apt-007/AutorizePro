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


# 构建 HTTP 请求消息
def makeMessage(self, messageInfo, removeOrNot, authorizeOrNot):
    requestInfo = self._helpers.analyzeRequest(messageInfo)
    headers = requestInfo.getHeaders()

    if removeOrNot:
        headers = list(headers)
        queryFlag = self.replaceQueryParam.isSelected()

        if queryFlag:
            param = self.replaceString.getText().split("=")
            paramKey = param[0]
            paramValue = param[1]
            pattern = r"([\?&]){}=.*?(?=[\s&])".format(paramKey)
            patchedHeader = re.sub(pattern, r"\1{}={}".format(paramKey, paramValue), headers[0], count=1,
                                   flags=re.DOTALL)
            headers[0] = patchedHeader
        else:
            removeHeaders = self.replaceString.getText()
            removeHeaders = [header for header in removeHeaders.split() if header.endswith(':')]
            for header in headers[:]:
                for removeHeader in removeHeaders:
                    if header.lower().startswith(removeHeader.lower()):
                        headers.remove(header)

        if authorizeOrNot:
            for k, v in self.badProgrammerMRModel.items():
                if v["type"] == "Headers (simple string):":
                    headers = map(lambda h: h.replace(v["match"], v["replace"]), headers)
                if v["type"] == "Headers (regex):":
                    headers = map(lambda h: re.sub(v["regexMatch"], v["replace"], h), headers)

            if not queryFlag:
                replaceStringLines = self.replaceString.getText().split("\n")
                for h in replaceStringLines:
                    if h == "":
                        pass
                    else:
                        headers.append(h)

    msgBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]

    if authorizeOrNot and msgBody is not None:
        msgBody = self._helpers.bytesToString(msgBody)
        for k, v in self.badProgrammerMRModel.items():
            if v["type"] == "Body (simple string):":
                msgBody = msgBody.replace(v["match"], v["replace"])
            if v["type"] == "Body (regex):":
                msgBody = re.sub(v["regexMatch"], v["replace"], msgBody)
        msgBody = self._helpers.stringToBytes(msgBody)

    return self._helpers.buildHttpMessage(headers, msgBody)


def getResponseHeaders(self, requestResponse):
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    return self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])


#  (!!!)  获取响应体的旧版本函数，暂时保留，观察新函数使用反馈
# def getResponseBody(self, requestResponse):
#     analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
#     return self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])

def getResponseBody(self, requestResponse):
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

    if any(header.lower().startswith("content-type:") and ("image" in header.lower() or "application/octet-stream" in header.lower()) for header in headers):
        return body_bytes

    try:
        return body_bytes.decode(charset)
    except (UnicodeDecodeError, LookupError) as e:
        self._callbacks.printError("Error decoding response body with charset %s: %s" % (charset, str(e)))
        # print("Response: ", body_bytes)
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