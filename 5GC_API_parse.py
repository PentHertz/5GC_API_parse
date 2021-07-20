#
#   5GC API Parse
#   A 5GC NF OpenAPI parser -  Burp Suite Extension
#   Author: Sebastien Dudek (@FlUxIuS) at https://penthertz.com
#

from burp import IBurpExtender, ITab 
from burp import IMessageEditorController, IContextMenuFactory
from javax import swing
from java.awt import (
    Font,
    BorderLayout,
    Color,
    Desktop,
    Button,
)
from java.awt.event import ActionListener
from javax.swing import (
    JButton,
    JFileChooser,
    JMenuItem,
)
from javax.swing.text import DefaultHighlighter
from java.util import LinkedList
from java.net import URI
import sys

from urlparse import urlparse
from utils.OpenAPI3GPP import *

__AUTHOR__ = "Sebastien Dudek (FlUxIuS)"
__VERSION__ = "1.2"

SWAGGER_URL = "https://jdegre.github.io/editor/?url=https://raw.githubusercontent.com/jdegre/5GC_APIs/master/"


try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class CallbackActionListener(ActionListener):
    def __init__(self, callback):
        ActionListener.__init__(self)
        self._callback = callback

    def actionPerformed(self, event):
        self._callback(event)


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
        toptextLabel = swing.JLabel('5GC Network Function parser (version 1.2)')
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
        self.tab.add("Center", self.tabbedPane)


        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return


    def clearTabs(self, event):
        """
            Clear all tabs
        """
        self.editboxes = []
        self.tab.remove(self.tabbedPane)
        self.tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", self.tabbedPane)


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

        urltobrowse = SWAGGER_URL + "/" +  self.textAreaFile.getText().split("/")[-1]
        btnswag = Button('Open similar API file\'s Swagger')
        btnswag.addActionListener(
            CallbackActionListener(lambda _: Desktop.getDesktop().browse(URI(urltobrowse)))
        )
        boxVertical.add(btnswag)
        ClearAllbutton = Button('Clear all', actionPerformed=self.clearTabs)
        boxVertical.add(ClearAllbutton)


try:
    FixBurpExceptions()
except:
    pass
