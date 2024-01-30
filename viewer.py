from PyQt5 import QtCore, QtGui, QtWidgets

class KeyViewerDialog(QtWidgets.QDialog):

    def __init__(self, parent):
        super().__init__(parent)
        self.settings()
    def settings(self):
        self.setObjectName("KeyViewerDialog")
        self.setFixedSize(563, 704)
        self.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
        self.setWindowFlag(QtCore.Qt.WindowType.WindowMinimizeButtonHint, True)

        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.setFont(font)
        self.verticalLayoutWidget = QtWidgets.QWidget(self)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(6, 5, 551, 692))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.keyViewerVerticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.keyViewerVerticalLayout.setContentsMargins(0, 0, 0, 0)
        self.keyViewerVerticalLayout.setSpacing(6)
        self.keyViewerVerticalLayout.setObjectName("keyViewerVerticalLayout")
        self.privateLabel = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.privateLabel.setObjectName("privateLabel")
        self.keyViewerVerticalLayout.addWidget(self.privateLabel)
        self.privateTextEdit = QtWidgets.QTextEdit(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(28)
        sizePolicy.setHeightForWidth(self.privateTextEdit.sizePolicy().hasHeightForWidth())
        self.privateTextEdit.setSizePolicy(sizePolicy)
        self.privateTextEdit.setReadOnly(True)
        self.privateTextEdit.setObjectName("privateTextEdit")
        self.keyViewerVerticalLayout.addWidget(self.privateTextEdit)
        self.publicLabel = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.publicLabel.setObjectName("publicLabel")
        self.keyViewerVerticalLayout.addWidget(self.publicLabel)
        self.publicTextEdit = QtWidgets.QTextEdit(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(10)
        sizePolicy.setHeightForWidth(self.publicTextEdit.sizePolicy().hasHeightForWidth())
        self.publicTextEdit.setSizePolicy(sizePolicy)
        self.publicTextEdit.setReadOnly(True)
        self.publicTextEdit.setObjectName("publicTextEdit")
        self.keyViewerVerticalLayout.addWidget(self.publicTextEdit)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("KeyViewerDialog", "RSA Key Viewer"))
        self.privateLabel.setText(_translate("KeyViewerDialog", "Private Key"))
        self.publicLabel.setText(_translate("KeyViewerDialog", "Public Key"))

    def setKeyInfo(self, prkey, pbkey):
        self.privateTextEdit.setText(prkey)
        self.publicTextEdit.setText(pbkey)