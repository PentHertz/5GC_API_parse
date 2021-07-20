#
#   5GC API Parse
#   A 5GC NF OpenAPI parser -  Burp Suite Extension
#   Author: Sebastien Dudek (@FlUxIuS) at https://penthertz.com
#

from burp import IBurpExtender, ITab 
from burp import IMessageEditorController, IContextMenuFactory
from javax import swing
from java.awt import Font
from java.awt import BorderLayout
from java.awt import Color
from java.awt import BorderLayout
from javax.swing import JButton
from javax.swing import JFileChooser
from javax.swing import JMenuItem
from javax.swing.text import DefaultHighlighter
from java.awt import Button
from java.util import LinkedList
import sys

import yaml
import json
from urlparse import urlparse


try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory):

    editboxes = []

    def registerExtenderCallbacks(self, callbacks):
        
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("5GC API Parse")
        self.callbacks.registerContextMenuFactory(self)
        self.helpers = callbacks.getHelpers();
 
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create panel
        textPanel = swing.JPanel()

        # Create boxes
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontalFile = swing.Box.createHorizontalBox()
        boxHorizontalPort = swing.Box.createHorizontalBox()


        # YAML file label
        toptextLabel = swing.JLabel('5GC Network Function parser (version 1.1)')
        boxHorizontal.add(toptextLabel)
        author = swing.JLabel('By @FlUxIuS at https://penthertz.com')
        
        # Set title font
        toptextLabel.setFont(Font('Courier New', Font.BOLD, 16))
        toptextLabel.setForeground(Color.RED)

        # URL text area
        self.textURL = swing.JTextArea('', 1, 100)
        self.textURL.setLineWrap(True)
        self.textURL.setText('https://target:8000/endpoint')
        self.textAreaFile = swing.JTextArea('', 1, 100)
        self.textAreaFile.setLineWrap(True)
        buttonFile = Button('Select File', actionPerformed=self.selectFile)

        boxHorizontalFile.add(self.textAreaFile)
        boxHorizontalFile.add(buttonFile)

        boxVertical.add(boxHorizontal)

        portLabel = swing.JLabel('Port:')
        boxHorizontalPort.add(portLabel)
        self.textPort = swing.JTextArea('', 1, 10)
        self.textPort.setLineWrap(True)
        self.textPort.setText('8000')           
        boxHorizontalPort.add(self.textPort)

        boxVertical.add(self.textURL)
        boxVertical.add(boxHorizontalPort)
        boxVertical.add(boxHorizontalFile)
        self.buttonParseFile = Button('Parse 3GPP OpenAPI file', actionPerformed=self.parseFile)
        boxVertical.add(self.buttonParseFile)

        # add author to vert box
        boxVertical.add(author)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        self.tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", self.tabbedPane);


        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return


    def selectFile(self, event):
        """
            SelectFile - Open file select popup
        """
        chooser = JFileChooser()
        retVal = chooser.showSaveDialog(None)
        self.textAreaFile.setText(chooser.selectedFile.path)


    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "5GC API Parse"
    

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab


    def parseFile(self, event):
        """
            Parse OpenAPI even
        """

        # First tab
        yamlfile = self.textAreaFile.getText()
        oapi = OpenAPI3GPP(yamlfile)
        paths = oapi.listpaths()
        parsedUrl = urlparse(self.textURL.getText())
        for path in paths:
            verbs = oapi.getEndPointVerbs(path)
            for verb in verbs:
                tag = oapi.getTags(path, verb)
                desc = oapi.getEndPointSummary(path, verb)
                params = oapi.dumpParameters(path, verb)
                reqpath = urlparse(self.textURL.getText()).path
                toreq = oapi.buildRequest(path, verb, reqpath, parsedUrl.netloc)
                body = oapi.dumpRequestBody(path, verb)

                #if len(body) == 0:
                params += "\n\n"+body
                self.createnewtab(tag, toreq, desc, params)


    def sendToRepeater(self, event):
        isHttps = False
        parsedUrl = urlparse(self.textURL.getText())
        if parsedUrl.scheme.lower() == "https":
            isHttps = True

        for name, b in self.editboxes:
            self.callbacks.sendToRepeater(
                parsedUrl.netloc.split(':')[0],
                int(self.textPort.getText()),
                isHttps,
                b.getMessage(),
                name
            );


    def createnewtab(self, name, content, desc, params):
        """
            Creates tabs for each endpoints.
                in(1): string name of the tab
                in(2): request content
                in(3): descripption string
                in(4): params strings
        """
        # Create boxes
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()

        summary = swing.JLabel('Summary')
        summary.setBorder(swing.BorderFactory.createEmptyBorder(10, 10, 10, 10))
        summary.setFont(Font('Courier New', Font.BOLD, 16))
        summary.setForeground(Color.RED)
        summaryText = swing.JLabel(desc)
        summaryText.setBorder(swing.BorderFactory.createEmptyBorder(10, 10, 10, 10))
       
        boxVertical.add(summary)
        boxVertical.add(summaryText)
        boxVertical.add(boxHorizontal)        

        tabedit = self.callbacks.createMessageEditor(self, True)
        self.editboxes.append((name, tabedit))
        boxHorizontal.add(tabedit.getComponent())

        self.tabbedPane.addTab(name, boxVertical)
        tabedit.setMessage(content, True);
        
        rightBox = swing.JPanel()
        rightBox.layout = BorderLayout()
        rightBox.border = swing.BorderFactory.createTitledBorder('Parameters')
        rTextArea = swing.JTextArea('', 15, 100)
        rTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(rTextArea)
        rightBox.add(scrollTextArea)
        boxHorizontal.add(rightBox)
        SendTobutton = Button('Send * to repeater', actionPerformed=self.sendToRepeater)
        boxVertical.add(SendTobutton)
        rTextArea.setText(params)


class OpenAPI3GPP(object):
    

    yamlinst = None


    def __init__(self, yamlfile):
        self.yamlinst = yaml.load(open(yamlfile), Loader=yaml.FullLoader)


    def listpaths(self):
        return [k for k, v in self.yamlinst['paths'].items()]

    
    def getEndPointVerbs(self, path):
        return [k for k, v in self.yamlinst['paths'][path].items()]


    def getEndPointSummary(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['summary']
        except:
            return None


    def getTags(self, path, verb):
        try:
            return ''.join(self.yamlinst['paths'][path][verb]['tags'])
        except:
            return None


    def getParameters(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['parameters']
        except:
            return []


    def getRequestBody(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['callbacks']
        except:
            return []


    def dumpParameters(self, path, verb):
        try:
            return yaml.dump(self.getParameters(path, verb))
        except:
            return None


    def dumpRequestBody(self, path, verb):
        try:
            return yaml.dump(self.getRequestBody(path, verb))
        except:
            return None


    def getRequestJSObject(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['requestBody']['content']['application/json']['schema']['$ref']
        except:
            return None


    def fetchObject(self, path):
        prop = self.yamlinst
        for k in path:
            prop = prop[k]
        return prop


    def getPropJSObject(self, path, verb):
        jsobj = self.getRequestJSObject(path, verb)
        paths = jsobj.split('/')[1:]
        obj = self.fetchObject(paths)
        required = obj['required']
        return (obj['properties'], required) 


    def buildJSObj(self, path, verb):
        props, reqs = self.getPropJSObject(path, verb)
        ojson = {}
        for k, v in props.items():
            if k in reqs:
                ojson[k] = 'required_value'
            else:
                ojson[k] = 'value'
        return repr(ojson)


    # default field values
    field_table = { 'Content-Encoding' : 'gzip, deflate',
                    'Accept-Encoding' : 'gzip, deflate',
                    'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
                    'Accept' : 'application/json',
    }


    def buildDefaultHeaders(self, netloc):
        string = ""
        string += 'Host: ' + netloc + "\r\n"
        string += 'User-Agent: ' + self.field_table['User-Agent'] + "\r\n"
        string += 'Accept: ' + self.field_table['Accept'] + "\r\n"
        return string


    def buildRequest(self, path, verb, reqpath, netloc):
        """
            Builds web request from YAML file
        """
        parameters = self.getParameters(path, verb)
        reqpath = self.yamlinst['servers'][0]['url'].format(apiRoot=reqpath) + path
        extrpath = ""
        headers = self.buildDefaultHeaders(netloc)
        body = "\r\n"
        reqstring = "{verb} {path} HTTP/1.1\r\n"
        for param in parameters:
            try:
                value = "{value}"
                if param['name'] in self.field_table:
                    value = self.field_table[param['name']]

                if param['in'] == 'header':
                    headers += "%s: %s\r\n" % (param['name'], value)
                elif param['in'] == 'query':
                    if extrpath == '':
                        extrpath += "?"
                    required = ''
                    if 'required' in param:
                        if param['required'] == True:
                            required = "required"
                    extrpath += "%s=%s&" % (param['name'], required)
            except:
                pass
        reqpath += extrpath[:-1] # delete last and op
        reqstring = reqstring.format(verb=verb.upper(), path=reqpath)
        reqstring += headers
        reqstring += "\n"
        reqObj = self.getRequestJSObject(path, verb)
        if reqObj is not None:
            reqstring += "\n"
            reqstring += self.buildJSObj(path, verb)
        return reqstring
            
try:
    FixBurpExceptions()
except:
    pass
