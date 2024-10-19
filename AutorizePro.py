#!/usr/bin/env python3
# coding: utf-8

"""
@File   : Autorize.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   :
"""

from burp import IBurpExtender, IHttpListener, IProxyListener
from authorization.authorization import handle_message
from helpers.initiator import Initiator
from helpers.filters import handle_proxy_message


class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("AutorizePro")

        initiator = Initiator(self)

        initiator.init_constants()

        initiator.draw_all()

        initiator.implement_all()

        initiator.init_ui()

        initiator.print_welcome_message()

        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        handle_message(self, toolFlag, messageIsRequest, messageInfo)

    def processProxyMessage(self, messageIsRequest, message):
        handle_proxy_message(self, message)