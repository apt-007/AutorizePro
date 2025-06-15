#!/usr/bin/env python3
# coding: utf-8

"""
@File   : save_restore.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   : 保存和恢复配置
"""

from javax.swing import SwingUtilities
from javax.swing import JFileChooser
from javax.swing import JFrame
from javax.swing import JCheckBox

from table import LogEntry, UpdateTableEDT
from helpers.http import get_cookie_header_from_message, get_authorization_header_from_message, IHttpRequestResponseImplementation

import csv, base64, json, re, sys
from java.io import File
from javax.swing.filechooser import FileNameExtensionFilter


maxInt = sys.maxsize
decrement = True
while decrement:
    decrement = False
    try:
        csv.field_size_limit(maxInt)
    except OverflowError:
        maxInt = int(maxInt/10)
        decrement = True


class SaveRestore():
    def __init__(self, extender):
        self._extender = extender
        self._checkBoxes = [
            "autoScroll",
            "ignore304",
            "prevent304",
            "interceptRequestsfromRepeater",
            "doUnauthorizedRequest",
            "replaceQueryParam",
            "showAuthBypassModified",
            "showAuthPotentiallyEnforcedModified",
            "showAuthEnforcedModified",
            "showAuthBypassUnauthenticated",
            "showAuthPotentiallyEnforcedUnauthenticated",
            "showAuthEnforcedUnauthenticated",
            "showDisabledUnauthenticated"
        ]

    def saveState(self):
        parentFrame = JFrame()
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("State output file")
        fileChooser.setSelectedFile(File("autorizepro_config.autorizepro"))
        userSelection = fileChooser.showSaveDialog(parentFrame)

        if userSelection == JFileChooser.APPROVE_OPTION:
            exportFile = fileChooser.getSelectedFile()
            filePath = exportFile.getAbsolutePath()
            if not filePath.lower().endswith(".autorizepro"):
                filePath += ".autorizepro"
                exportFile = File(filePath)
                
            with open(exportFile.getAbsolutePath(), 'wb') as csvfile:
                csvwriter = csv.writer(csvfile, delimiter='\t', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                tempRow = ["ReplaceString", base64.b64encode(self._extender.replaceString.getText())]
                csvwriter.writerow(tempRow)
                
                # 保存API密钥
                if hasattr(self._extender, "apiKeyField"):
                    tempRow = ["ApiKey", base64.b64encode(self._extender.apiKeyField.getText())]
                    csvwriter.writerow(tempRow)
                
                # 保存模型选择
                if hasattr(self._extender, "aiModelTextField"):
                    try:
                        # 直接从文本框获取模型名称
                        modelName = self._extender.aiModelTextField.getText()
                        # 确保模型名称是字符串
                        if modelName is not None and modelName != "":
                            tempRow = ["AiModel", str(modelName)]
                            csvwriter.writerow(tempRow)
                    except:
                        pass

                for EDFilter in self._extender.EDModel.toArray():
                    tempRow = ["EDFilter", base64.b64encode(EDFilter)]
                    csvwriter.writerow(tempRow)

                for EDFilterUnauth in self._extender.EDModelUnauth.toArray():
                    tempRow = ["EDFilterUnauth", base64.b64encode(EDFilterUnauth)]
                    csvwriter.writerow(tempRow)

                for IFFilter in self._extender.IFModel.toArray():
                    tempRow = ["IFFilter", base64.b64encode(IFFilter)]
                    csvwriter.writerow(tempRow)

                for t in ["AndOrType", "AndOrTypeUnauth"]:
                    tempRow = [t, getattr(self._extender, t).getSelectedItem()]
                    csvwriter.writerow(tempRow)

                # 保存Temporary headers（只保存type为Headers (simple string): 和 Headers (regex): 的项，避免和MatchReplace混淆）
                for key in self._extender.badProgrammerMRModel:
                    d = dict(self._extender.badProgrammerMRModel[key])
                    d["regexMatch"] = d["regexMatch"] is not None
                    # 只保存Headers类型的临时header
                    if d["type"].startswith("Headers"):
                        tempRow = ["TemporaryHeader", base64.b64encode(json.dumps(d))]
                        csvwriter.writerow(tempRow)

                d = dict((c, getattr(self._extender, c).isSelected()) for c in self._checkBoxes)
                tempRow = ["CheckBoxes", json.dumps(d)]
                csvwriter.writerow(tempRow)

                # 修复exportPnl最后一个组件不是JCheckBox时报错的问题
                component = self._extender.exportPnl.getComponents()[-1]
                if isinstance(component, JCheckBox):
                    isSelected = component.isSelected()
                else:
                    isSelected = False
                tempRow = ["RemoveDuplicates", json.dumps(isSelected)]
                csvwriter.writerow(tempRow)

                # 保存所有自定义header配置（savedHeaders）
                print("[DEBUG] saveState: savedHeaders count:", len(self._extender.savedHeaders))
                for headerObj in self._extender.savedHeaders:
                    tempRow = ["SavedHeader", base64.b64encode(json.dumps(headerObj))]
                    csvwriter.writerow(tempRow)

                # Request/response list
                for i in range(0,self._extender._log.size()):
                    tempRequestResponseHost = self._extender._log.get(i)._requestResponse.getHttpService().getHost()
                    tempRequestResponsePort = self._extender._log.get(i)._requestResponse.getHttpService().getPort()
                    tempRequestResponseProtocol = self._extender._log.get(i)._requestResponse.getHttpService().getProtocol()
                    tempRequestResponseRequest = base64.b64encode(self._extender._log.get(i)._requestResponse.getRequest())
                    tempRequestResponseResponse = base64.b64encode(self._extender._log.get(i)._requestResponse.getResponse())

                    tempOriginalRequestResponseHost = self._extender._log.get(i)._originalrequestResponse.getHttpService().getHost()
                    tempOriginalRequestResponsePort = self._extender._log.get(i)._originalrequestResponse.getHttpService().getPort()
                    tempOriginalRequestResponseProtocol = self._extender._log.get(i)._originalrequestResponse.getHttpService().getProtocol()
                    tempOriginalRequestResponseRequest = base64.b64encode(self._extender._log.get(i)._originalrequestResponse.getRequest())
                    tempOriginalRequestResponseResponse = base64.b64encode(self._extender._log.get(i)._originalrequestResponse.getResponse())

                    if self._extender._log.get(i)._unauthorizedRequestResponse is not None:
                        tempUnauthorizedRequestResponseHost = self._extender._log.get(i)._unauthorizedRequestResponse.getHttpService().getHost()
                        tempUnauthorizedRequestResponsePort = self._extender._log.get(i)._unauthorizedRequestResponse.getHttpService().getPort()
                        tempUnauthorizedRequestResponseProtocol = self._extender._log.get(i)._unauthorizedRequestResponse.getHttpService().getProtocol()
                        tempUnauthorizedRequestResponseRequest = base64.b64encode(self._extender._log.get(i)._unauthorizedRequestResponse.getRequest())
                        tempUnauthorizedRequestResponseResponse = base64.b64encode(self._extender._log.get(i)._unauthorizedRequestResponse.getResponse())
                    else:
                        tempUnauthorizedRequestResponseHost = None
                        tempUnauthorizedRequestResponsePort = None
                        tempUnauthorizedRequestResponseProtocol = None
                        tempUnauthorizedRequestResponseRequest = None
                        tempUnauthorizedRequestResponseResponse = None

                    tempEnforcementStatus = self._extender._log.get(i)._enfocementStatus
                    tempEnforcementStatusUnauthorized = self._extender._log.get(i)._enfocementStatusUnauthorized

                    tempRow = [tempRequestResponseHost,tempRequestResponsePort,tempRequestResponseProtocol,tempRequestResponseRequest,tempRequestResponseResponse]
                    tempRow.extend([tempOriginalRequestResponseHost,tempOriginalRequestResponsePort,tempOriginalRequestResponseProtocol,tempOriginalRequestResponseRequest,tempOriginalRequestResponseResponse])
                    tempRow.extend([tempUnauthorizedRequestResponseHost,tempUnauthorizedRequestResponsePort,tempUnauthorizedRequestResponseProtocol,tempUnauthorizedRequestResponseRequest,tempUnauthorizedRequestResponseResponse])
                    tempRow.extend([tempEnforcementStatus,tempEnforcementStatusUnauthorized])

                    csvwriter.writerow(tempRow)

    def restoreState(self):
        parentFrame = JFrame()
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("State import file")
        
        # 添加文件过滤器，只显示.autorizepro文件
        # 使用英文描述避免乱码问题
        fileFilter = FileNameExtensionFilter("AutorizePro Config Files (*.autorizepro)", ["autorizepro"])
        fileChooser.addChoosableFileFilter(fileFilter)
        fileChooser.setFileFilter(fileFilter)
        
        userSelection = fileChooser.showDialog(parentFrame, "Restore")
        modelMap = {
            "IFFilter": self._extender.IFModel,
            "EDFilter": self._extender.EDModel,
            "EDFilterUnauth": self._extender.EDModelUnauth
        }

        if userSelection == JFileChooser.APPROVE_OPTION:
            importFile = fileChooser.getSelectedFile()

            with open(importFile.getAbsolutePath(), 'r') as csvfile:

                csvreader = csv.reader(csvfile, delimiter='\t', quotechar='|')

                self._extender.savedHeaders = []  # 还原前先清空
                for row in csvreader:
                    if row[0] == "ReplaceString":
                        self._extender.replaceString.setText(base64.b64decode(row[1]))
                        continue
                    
                    if row[0] == "ApiKey" and hasattr(self._extender, "apiKeyField"):
                        self._extender.apiKeyField.setText(base64.b64decode(row[1]))
                        continue
                    
                    if row[0] == "AiModel" and hasattr(self._extender, "aiModelTextField"):
                        try:
                            self._extender.aiModelTextField.setText(row[1])
                        except Exception as e:
                            pass
                        continue

                    if row[0] in modelMap:
                        f = base64.b64decode(row[1])
                        if f not in modelMap[row[0]].toArray():
                            modelMap[row[0]].addElement(f)
                        continue

                    if row[0] in {"AndOrType", "AndOrTypeUnauth"}:
                        getattr(self._extender, row[0]).setSelectedItem(row[1])
                        continue

                    if row[0] == "MatchReplace":
                        d = json.loads(base64.b64decode(row[1]))
                        key = d["type"] + " " + d["match"] + "->" + d["replace"]
                        if key in self._extender.badProgrammerMRModel:
                            continue
                        regexMatch = None
                        if d["regexMatch"]:
                            try:
                                d["regexMatch"] = re.compile(d["match"])
                            except re.error:
                                continue
                        self._extender.badProgrammerMRModel[key] = d
                        self._extender.MRModel.addElement(key)
                        continue

                    if row[0] == "TemporaryHeader":
                        d = json.loads(base64.b64decode(row[1]))
                        key = d["type"] + " " + d["match"] + "->" + d["replace"]
                        if key in self._extender.badProgrammerMRModel:
                            continue
                        regexMatch = None
                        if d["regexMatch"]:
                            try:
                                d["regexMatch"] = re.compile(d["match"])
                            except re.error:
                                continue
                        self._extender.badProgrammerMRModel[key] = d
                        self._extender.MRModel.addElement(key)
                        continue

                    if row[0] == "CheckBoxes":
                        d = json.loads(row[1])
                        for k in d:
                            getattr(self._extender, k).setSelected(d[k])
                        continue

                    if row[0] == "RemoveDuplicates":
                        isSelected = json.loads(row[1])
                        try:
                            from javax.swing import JCheckBox
                            component = self._extender.exportPnl.getComponents()[-1]
                            if isinstance(component, JCheckBox):
                                component.setSelected(isSelected)
                            # 否则什么都不做，避免报错
                        except TypeError:
                            pass
                        continue

                    if row[0] == "SavedHeader":
                        headerObj = json.loads(base64.b64decode(row[1]))
                        self._extender.savedHeaders.append(headerObj)
                        continue

                    tempRequestResponseHost = row[0]
                    tempRequestResponsePort = row[1]
                    tempRequestResponseProtocol = row[2]
                    tempRequestResponseRequest = base64.b64decode(row[3])
                    tempRequestResponseResponse = base64.b64decode(row[4])

                    tempRequestResponseHttpService = self._extender._helpers.buildHttpService(tempRequestResponseHost,int(tempRequestResponsePort),tempRequestResponseProtocol)
                    tempRequestResponse = IHttpRequestResponseImplementation(tempRequestResponseHttpService,tempRequestResponseRequest,tempRequestResponseResponse)

                    tempOriginalRequestResponseHost = row[5]
                    tempOriginalRequestResponsePort = row[6]
                    tempOriginalRequestResponseProtocol = row[7]
                    tempOriginalRequestResponseRequest = base64.b64decode(row[8])
                    tempOriginalRequestResponseResponse = base64.b64decode(row[9])

                    tempOriginalRequestResponseHttpService = self._extender._helpers.buildHttpService(tempOriginalRequestResponseHost,int(tempOriginalRequestResponsePort),tempOriginalRequestResponseProtocol)
                    tempOriginalRequestResponse = IHttpRequestResponseImplementation(tempOriginalRequestResponseHttpService,tempOriginalRequestResponseRequest,tempOriginalRequestResponseResponse)

                    checkAuthentication = True
                    if row[10] != '':
                        tempUnauthorizedRequestResponseHost = row[10]
                        tempUnauthorizedRequestResponsePort = row[11]
                        tempUnauthorizedRequestResponseProtocol = row[12]
                        tempUnauthorizedRequestResponseRequest = base64.b64decode(row[13])
                        tempUnauthorizedRequestResponseResponse = base64.b64decode(row[14])
                        tempUnauthorizedRequestResponseHttpService = self._extender._helpers.buildHttpService(tempUnauthorizedRequestResponseHost,int(tempUnauthorizedRequestResponsePort),tempUnauthorizedRequestResponseProtocol)
                        tempUnauthorizedRequestResponse = IHttpRequestResponseImplementation(tempUnauthorizedRequestResponseHttpService,tempUnauthorizedRequestResponseRequest,tempUnauthorizedRequestResponseResponse)
                    else:
                        checkAuthentication = False
                        tempUnauthorizedRequestResponse = None

                    tempEnforcementStatus = row[15]
                    tempEnforcementStatusUnauthorized = row[16]

                    # 使用try-finally确保锁始终被释放
                    self._extender._lock.acquire()
                    try:
                        row = self._extender._log.size()

                        if checkAuthentication:
                            self._extender._log.add(
                                LogEntry(self._extender.currentRequestNumber,
                                self._extender._callbacks.saveBuffersToTempFiles(tempRequestResponse),
                                 self._extender._helpers.analyzeRequest(tempRequestResponse).getMethod(),
                                  self._extender._helpers.analyzeRequest(tempRequestResponse).getUrl(),
                                   self._extender._callbacks.saveBuffersToTempFiles(tempOriginalRequestResponse),
                                   tempEnforcementStatus,
                                   self._extender._callbacks.saveBuffersToTempFiles(tempUnauthorizedRequestResponse),
                                   tempEnforcementStatusUnauthorized))
                        else:
                            self._extender._log.add(
                                LogEntry(self._extender.currentRequestNumber,
                                self._extender._callbacks.saveBuffersToTempFiles(tempRequestResponse),
                                self._extender._helpers.analyzeRequest(tempRequestResponse).getMethod(),
                                 self._extender._helpers.analyzeRequest(tempRequestResponse).getUrl(),
                                  self._extender._callbacks.saveBuffersToTempFiles(tempOriginalRequestResponse),
                                  tempEnforcementStatus,None,tempEnforcementStatusUnauthorized))

                        SwingUtilities.invokeLater(UpdateTableEDT(self._extender,"insert",row,row))
                        self._extender.currentRequestNumber = self._extender.currentRequestNumber + 1
                    finally:
                        self._extender._lock.release()

                lastRow = self._extender._log.size()
                if lastRow > 0:
                    cookiesHeader = get_cookie_header_from_message(self._extender, self._extender._log.get(lastRow - 1)._requestResponse)
                    if cookiesHeader:
                        self._extender.lastCookiesHeader = cookiesHeader
                        self._extender.fetchCookiesHeaderButton.setEnabled(True)
                    authorizationHeader = get_authorization_header_from_message(self._extender, self._extender._log.get(lastRow - 1)._requestResponse)
                    if authorizationHeader:
                        self._extender.lastAuthorizationHeader = authorizationHeader
                        self._extender.fetchAuthorizationHeaderButton.setEnabled(True)

                print("[DEBUG] restoreState: savedHeaders count:", len(self._extender.savedHeaders))
                # 还原完所有SavedHeader后，刷新下拉框并选中第一个，触发事件同步内容
                if hasattr(self._extender, 'savedHeadersTitlesCombo'):
                    from javax.swing import DefaultComboBoxModel
                    self._extender.savedHeadersTitlesCombo.setModel(DefaultComboBoxModel(
                        [x['title'] for x in self._extender.savedHeaders]
                    ))
                    if self._extender.savedHeaders:
                        self._extender.savedHeadersTitlesCombo.setSelectedIndex(0)
                        from java.awt.event import ActionEvent
                        event = ActionEvent(self._extender.savedHeadersTitlesCombo, ActionEvent.ACTION_PERFORMED, "restore")
                        for listener in self._extender.savedHeadersTitlesCombo.getActionListeners():
                            listener.actionPerformed(event)
