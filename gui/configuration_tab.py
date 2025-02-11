#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@File   : configuration_tab.py
@Author : sule01u
@Date   : 2024/10/10
@Desc   :
"""

from javax.swing import DefaultComboBoxModel
from java.awt.event import ActionListener
from javax.swing import SwingUtilities
from javax.swing import JToggleButton
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JOptionPane
from javax.swing import GroupLayout
from javax.swing import JSplitPane
from javax.swing import JComboBox
from javax.swing import JTextArea
from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextField
from java.awt import Dimension

from table import UpdateTableEDT


class ConfigurationTab():
    def __init__(self, extender):
        self._extender = extender

    def draw(self):
        """  init configuration tab
        """
        self.DEFUALT_REPLACE_TEXT = "Cookie: Insert=injected; cookie=or;\nHeader: here"
        self._extender.startButton = JToggleButton("AutorizePro is off", actionPerformed=self.startOrStop)
        self._extender.startButton.setBounds(10, 20, 230, 30)

        self._extender.apiKeyField = JTextField(20)
        self._extender.apiKeyField.setBounds(50, 100, 200, 30)
        self._extender.apiKeyEnabledCheckbox = JCheckBox("KEY")
        self._extender.apiKeyEnabledCheckbox.setBounds(10, 60, 100, 30)
        predefinedOptions = ["qwen-turbo", "qwen-plus", "qwen-max", "deepseek-chat","deepseek-reasoner","gpt-4o-mini", "gpt-4o", "glm-4-flash", "glm-4-air", "hunyuan-standard", "hunyuan-large",]
        self._extender.aiOptionComboBox = JComboBox(predefinedOptions)
        self._extender.aiOptionComboBox.setBounds(50, 140, 200, 30)
        self._extender.aiOptionComboBox.setSelectedItem("qwen-turbo")

        self._extender.clearButton = JButton("Clear List", actionPerformed=self.clearList)
        self._extender.clearButton.setBounds(10, 80, 100, 30)
        self._extender.autoScroll = JCheckBox("Auto Scroll")
        self._extender.autoScroll.setBounds(145, 80, 130, 30)

        self._extender.ignore304 = JCheckBox("Ignore 304/204 status code responses")
        self._extender.ignore304.setBounds(280, 5, 300, 30)
        self._extender.ignore304.setSelected(True)

        self._extender.prevent304 = JCheckBox("Prevent 304 Not Modified status code")
        self._extender.prevent304.setBounds(280, 25, 300, 30)
        self._extender.interceptRequestsfromRepeater = JCheckBox("Intercept requests from Repeater")
        self._extender.interceptRequestsfromRepeater.setBounds(280, 45, 300, 30)

        self._extender.doUnauthorizedRequest = JCheckBox("Check unauthenticated")
        self._extender.doUnauthorizedRequest.setBounds(280, 65, 300, 30)
        self._extender.doUnauthorizedRequest.setSelected(True)

        self._extender.replaceQueryParam = JCheckBox("Replace query params", actionPerformed=self.replaceQueryHanlder)
        self._extender.replaceQueryParam.setBounds(280, 85, 300, 30)
        self._extender.replaceQueryParam.setSelected(False)

        savedHeadersTitles = self.getSavedHeadersTitles()
        self._extender.savedHeadersTitlesCombo = JComboBox(savedHeadersTitles)
        self._extender.savedHeadersTitlesCombo.addActionListener(SavedHeaderChange(self._extender))
        self._extender.savedHeadersTitlesCombo.setBounds(10, 115, 100, 30)

        self._extender.saveHeadersButton = JButton("Add", actionPerformed=self.saveHeaders)
        self._extender.saveHeadersButton.setBounds(100, 115, 80, 30)

        self._extender.removeHeadersButton = JButton("Remove", actionPerformed=self.removeHeaders)
        self._extender.removeHeadersButton.setBounds(200, 115, 80, 30)

        self._extender.replaceString = JTextArea(self.DEFUALT_REPLACE_TEXT, 5, 30)
        self._extender.replaceString.setWrapStyleWord(True)
        self._extender.replaceString.setLineWrap(True)

        scrollReplaceString = JScrollPane(self._extender.replaceString)
        scrollReplaceString.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scrollReplaceString.setBounds(10, 150, 470, 150)

        fromLastRequestLabel = JLabel("From last request:")
        fromLastRequestLabel.setBounds(10, 305, 250, 30)

        self._extender.fetchCookiesHeaderButton = JButton("Fetch Cookies header",
                                                          actionPerformed=self.fetchCookiesHeader)
        self._extender.fetchCookiesHeaderButton.setEnabled(False)
        self._extender.fetchCookiesHeaderButton.setBounds(10, 330, 220, 30)

        self._extender.fetchAuthorizationHeaderButton = JButton("Fetch Authorization header",
                                                                actionPerformed=self.fetchAuthorizationHeader)
        self._extender.fetchAuthorizationHeaderButton.setEnabled(False)
        self._extender.fetchAuthorizationHeaderButton.setBounds(260, 330, 220, 30)

        self._extender.filtersTabs = JTabbedPane()
        self._extender.filtersTabs = self._extender.filtersTabs
        self._extender.filtersTabs.addTab("Privilege Enforcement Rules", self._extender.EDPnl)
        self._extender.filtersTabs.addTab("Unauthorized Enforcement Rules", self._extender.EDPnlUnauth)
        self._extender.filtersTabs.addTab("Interception Filters", self._extender.filtersPnl)
        self._extender.filtersTabs.addTab("Match/Replace", self._extender.MRPnl)
        self._extender.filtersTabs.addTab("Table Filter", self._extender.filterPnl)
        self._extender.filtersTabs.addTab("Save/Restore", self._extender.exportPnl)

        self._extender.filtersTabs.setSelectedIndex(2)
        self._extender.filtersTabs.setBounds(0, 350, 2000, 700)

        self.config_pnl = JPanel()
        layout = GroupLayout(self.config_pnl)
        self.config_pnl.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(
                layout.createParallelGroup()
                .addComponent(
                    self._extender.startButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addGroup(
                    layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                    .addComponent(
                        self._extender.apiKeyEnabledCheckbox,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                    .addComponent(
                        self._extender.apiKeyField,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    )
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                    .addComponent(
                        self._extender.aiOptionComboBox,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    )
                )
                .addComponent(
                    self._extender.clearButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addGroup(layout.createSequentialGroup()
                .addComponent(
                    self._extender.savedHeadersTitlesCombo,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.saveHeadersButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.removeHeadersButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                ))
                .addComponent(
                    scrollReplaceString,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    fromLastRequestLabel,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addGroup(layout.createSequentialGroup()
                .addComponent(
                    self._extender.fetchCookiesHeaderButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.fetchAuthorizationHeaderButton,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                )
            )
            .addGroup(
                layout.createParallelGroup()
                .addComponent(
                    self._extender.ignore304,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.prevent304,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.interceptRequestsfromRepeater,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.doUnauthorizedRequest,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.autoScroll,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.replaceQueryParam,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
            )
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(
                self._extender.startButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.ignore304,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            )
            .addComponent(
                self._extender.prevent304,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.CENTER)
            .addComponent(
                self._extender.apiKeyEnabledCheckbox,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.apiKeyField,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.aiOptionComboBox,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.interceptRequestsfromRepeater,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            )
            .addComponent(
                self._extender.doUnauthorizedRequest,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.replaceQueryParam,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(
                self._extender.clearButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.autoScroll,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            )
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(
                self._extender.savedHeadersTitlesCombo,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.saveHeadersButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.removeHeadersButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            ))
            .addComponent(
                scrollReplaceString,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                fromLastRequestLabel,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
            .addComponent(
                self._extender.fetchCookiesHeaderButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            )
            .addComponent(
                self._extender.fetchAuthorizationHeaderButton,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
                GroupLayout.PREFERRED_SIZE,
            ))
        )

        self.config_pnl.setMinimumSize(Dimension(0, 0))
        self.config_pnl.setPreferredSize(Dimension(400, 200))

        self._extender.filtersTabs.setMinimumSize(Dimension(0, 0))
        self._extender.filtersTabs.setPreferredSize(Dimension(400, 400))

        self._extender._cfg_splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._extender._cfg_splitpane.setResizeWeight(0.5)
        self._extender._cfg_splitpane.setContinuousLayout(True)
        self._extender._cfg_splitpane.setLeftComponent(self.config_pnl)
        self._extender._cfg_splitpane.setRightComponent(self._extender.filtersTabs)

    def startOrStop(self, event):
        if self._extender.startButton.getText() == "AutorizePro is off":
            self._extender.startButton.setText("AutorizePro is on")
            self._extender.startButton.setSelected(True)
            self._extender.intercept = 1
        else:
            self._extender.startButton.setText("AutorizePro is off")
            self._extender.startButton.setSelected(False)
            self._extender.intercept = 0

    def clearList(self, event):
        self._extender._lock.acquire()
        oldSize = self._extender._log.size()
        self._extender._log.clear()
        SwingUtilities.invokeLater(UpdateTableEDT(self._extender, "delete", 0, oldSize - 1))
        self._extender._lock.release()

    def replaceQueryHanlder(self, event):
        if self._extender.replaceQueryParam.isSelected():
            self._extender.replaceString.setText("paramName=paramValue\npath:oldPath=newPath")
        else:
            self._extender.replaceString.setText(self.DEFUALT_REPLACE_TEXT)

    def saveHeaders(self, event):
        savedHeadersTitle = JOptionPane.showInputDialog("Please provide saved headers title:")
        self._extender.savedHeaders.append(
            {'title': savedHeadersTitle, 'headers': self._extender.replaceString.getText()})
        self._extender.savedHeadersTitlesCombo.setModel(DefaultComboBoxModel(self.getSavedHeadersTitles()))
        self._extender.savedHeadersTitlesCombo.getModel().setSelectedItem(savedHeadersTitle)

    def removeHeaders(self, event):
        model = self._extender.savedHeadersTitlesCombo.getModel()
        selectedItem = model.getSelectedItem()
        if selectedItem == "Temporary headers":
            return

        delObject = None
        for savedHeaderObj in self._extender.savedHeaders:
            if selectedItem == savedHeaderObj['title']:
                delObject = savedHeaderObj
        self._extender.savedHeaders.remove(delObject)
        model.removeElement(selectedItem)

    def getSavedHeadersTitles(self):
        titles = []
        for savedHeaderObj in self._extender.savedHeaders:
            titles.append(savedHeaderObj['title'])
        return titles

    def fetchCookiesHeader(self, event):
        if self._extender.lastCookiesHeader:
            self._extender.replaceString.setText(self._extender.lastCookiesHeader)

    def fetchAuthorizationHeader(self, event):
        if self._extender.lastAuthorizationHeader:
            self._extender.replaceString.setText(self._extender.lastAuthorizationHeader)


class SavedHeaderChange(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        selectedTitle = self._extender.savedHeadersTitlesCombo.getSelectedItem()
        headers = [x for x in self._extender.savedHeaders if x['title'] == selectedTitle]
        self._extender.replaceString.setText(headers[0]['headers'])

