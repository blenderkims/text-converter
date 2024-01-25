from PyQt5 import QtCore, QtGui, QtWidgets
from converter import AESEncrypt, SHAHash, B64Encode
from converter import AES_DEFAULT_PASSWORD, AES_DEFAULT_SALT, SHA_ALGORITHM, OUTPUT_FORMAT
import resources

class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.init()
        self.settings()

    def init(self):
        self.aes = AESEncrypt()
        self.sha = SHAHash()
        self.b64 = B64Encode()

    def settings(self):
        # MainWindow Settings
        self.setObjectName("MainWindow")
        self.setWindowModality(QtCore.Qt.WindowModality.WindowModal)
        self.setEnabled(True)
        self.setFixedSize(692, 395)
        self.setWindowFlag(QtCore.Qt.WindowType.WindowMinimizeButtonHint, True)
        self.setWindowFlag(QtCore.Qt.WindowType.WindowStaysOnTopHint, True)
        self.setWindowIcon(QtGui.QIcon(":/icons/icon.png"))

        # Main Widget
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.setCentralWidget(self.centralwidget)

        # Tab Widget
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(3, 3, 687, 388))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.tabWidget.setFont(font)
        self.tabWidget.setObjectName("tabWidget")

        # AES Tab Widget
        self.aesTab = QtWidgets.QWidget()
        self.aesTab.setObjectName("aesTab")
        self.tabWidget.addTab(self.aesTab, "")

        # AES Settings Group Box
        self.aesSettingsGroupBox = QtWidgets.QGroupBox(self.aesTab)
        self.aesSettingsGroupBox.setGeometry(QtCore.QRect(5, 4, 671, 88))
        self.aesSettingsGroupBox.setObjectName("aesSettingsGroupBox")

        # AES Settings Radio Grid Layout
        self.aesRadioGridLayoutWidget = QtWidgets.QWidget(self.aesSettingsGroupBox)
        self.aesRadioGridLayoutWidget.setGeometry(QtCore.QRect(8, 14, 263, 70))
        self.aesRadioGridLayoutWidget.setObjectName("aesRadioGridLayoutWidget")
        self.aesRadioGridLayout = QtWidgets.QGridLayout(self.aesRadioGridLayoutWidget)
        self.aesRadioGridLayout.setContentsMargins(0, 0, 0, 0)
        self.aesRadioGridLayout.setObjectName("aesRadioGridLayout")

        # AES Settings Method Radio Buttons Group
        self.aesMethodLabel = QtWidgets.QLabel(self.aesRadioGridLayoutWidget)
        self.aesMethodLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.aesMethodLabel.setObjectName("aesMethodLabel")
        self.aesRadioGridLayout.addWidget(self.aesMethodLabel, 0, 0, 1, 1)

        self.aesEncryptRadioBtn = QtWidgets.QRadioButton(self.aesRadioGridLayoutWidget)
        self.aesEncryptRadioBtn.setChecked(True)
        self.aesEncryptRadioBtn.setObjectName("aesEncryptRadioBtn")
        self.aesEncryptRadioBtn.toggled.connect(self.aesMethodRadioChanged)
        self.aesRadioGridLayout.addWidget(self.aesEncryptRadioBtn, 0, 1, 1, 1)

        self.aesDescryptRadioBtn = QtWidgets.QRadioButton(self.aesRadioGridLayoutWidget)
        self.aesDescryptRadioBtn.setObjectName("aesDescryptRadioBtn")
        self.aesRadioGridLayout.addWidget(self.aesDescryptRadioBtn, 0, 2, 1, 1)

        self.aesMethodButtonGroup = QtWidgets.QButtonGroup(self)
        self.aesMethodButtonGroup.setObjectName("aesMethodButtonGroup")
        self.aesMethodButtonGroup.addButton(self.aesEncryptRadioBtn)
        self.aesMethodButtonGroup.addButton(self.aesDescryptRadioBtn)

        # AES Settings Format Radio Buttons Group
        self.aesFormatLabel = QtWidgets.QLabel(self.aesRadioGridLayoutWidget)
        self.aesFormatLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.aesFormatLabel.setObjectName("aesFormatLabel")
        self.aesRadioGridLayout.addWidget(self.aesFormatLabel, 1, 0, 1, 1)

        self.aesHexRadioBtn = QtWidgets.QRadioButton(self.aesRadioGridLayoutWidget)
        self.aesHexRadioBtn.setChecked(True)
        self.aesHexRadioBtn.setObjectName("aesHexRadioBtn")
        self.aesHexRadioBtn.toggled.connect(self.aesFormatRadioChanged)
        self.aesRadioGridLayout.addWidget(self.aesHexRadioBtn, 1, 1, 1, 1)

        self.aesB64RadioBtn = QtWidgets.QRadioButton(self.aesRadioGridLayoutWidget)
        self.aesB64RadioBtn.setObjectName("aesB64RadioBtn")
        self.aesRadioGridLayout.addWidget(self.aesB64RadioBtn, 1, 2, 1, 1)

        self.aesFormatButtonGroup = QtWidgets.QButtonGroup(self)
        self.aesFormatButtonGroup.setObjectName("aesFormatButtonGroup")
        self.aesFormatButtonGroup.addButton(self.aesHexRadioBtn)
        self.aesFormatButtonGroup.addButton(self.aesB64RadioBtn)

        # AES Settings Text Grid Layout
        self.aesTextGridLayoutWidget = QtWidgets.QWidget(self.aesSettingsGroupBox)
        self.aesTextGridLayoutWidget.setGeometry(QtCore.QRect(280, 14, 383, 70))
        self.aesTextGridLayoutWidget.setObjectName("aesTextGridLayoutWidget")
        self.aesTextGridLayout = QtWidgets.QGridLayout(self.aesTextGridLayoutWidget)
        self.aesTextGridLayout.setContentsMargins(5, 0, 5, 0)
        self.aesTextGridLayout.setObjectName("aesTextGridLayout")

        # AES Settings Password Text Edit
        self.aesPasswordLabel = QtWidgets.QLabel(self.aesTextGridLayoutWidget)
        self.aesPasswordLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.aesPasswordLabel.setObjectName("aesPasswordLabel")
        self.aesTextGridLayout.addWidget(self.aesPasswordLabel, 0, 0, 1, 1)

        self.aesPasswordLineEdit = QtWidgets.QLineEdit(self.aesTextGridLayoutWidget)
        self.aesPasswordLineEdit.setObjectName("aesPasswordLineEdit")
        self.aesPasswordLineEdit.setText(AES_DEFAULT_PASSWORD)
        self.aesPasswordLineEdit.textChanged.connect(self.aesInputTextChanged)
        self.aesTextGridLayout.addWidget(self.aesPasswordLineEdit, 0, 1, 1, 1)

        # AES Settings Salt Text Edit
        self.aesSaltLabel = QtWidgets.QLabel(self.aesTextGridLayoutWidget)
        self.aesSaltLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.aesSaltLabel.setObjectName("aesSaltLabel")
        self.aesTextGridLayout.addWidget(self.aesSaltLabel, 1, 0, 1, 1)

        self.aesSaltLineEdit = QtWidgets.QLineEdit(self.aesTextGridLayoutWidget)
        self.aesSaltLineEdit.setObjectName("aesSaltLineEdit")
        self.aesSaltLineEdit.setText(AES_DEFAULT_SALT)
        self.aesSaltLineEdit.textChanged.connect(self.aesInputTextChanged)
        self.aesTextGridLayout.addWidget(self.aesSaltLineEdit, 1, 1, 1, 1)

        # AES InOut Vertical Layout
        self.aesInOutVerticalLayoutWidget = QtWidgets.QWidget(self.aesTab)
        self.aesInOutVerticalLayoutWidget.setGeometry(QtCore.QRect(5, 99, 671, 253))
        self.aesInOutVerticalLayoutWidget.setObjectName("aesInOutVerticalLayoutWidget")
        self.aesInOutVerticalLayout = QtWidgets.QVBoxLayout(self.aesInOutVerticalLayoutWidget)
        self.aesInOutVerticalLayout.setContentsMargins(0, 0, 0, 0)
        self.aesInOutVerticalLayout.setObjectName("aesInOutVerticalLayout")

        # AES Input Text Edit
        self.aesInputLabel = QtWidgets.QLabel(self.aesInOutVerticalLayoutWidget)
        self.aesInputLabel.setObjectName("aesInputLabel")
        self.aesInOutVerticalLayout.addWidget(self.aesInputLabel)
        self.aesInputTextEdit = QtWidgets.QTextEdit(self.aesInOutVerticalLayoutWidget)
        self.aesInputTextEdit.setObjectName("aesInputTextEdit")
        self.aesInputTextEdit.textChanged.connect(self.aesInputTextChanged)
        self.aesInOutVerticalLayout.addWidget(self.aesInputTextEdit)

        # AES Output Text Edit
        self.aesOutputLabel = QtWidgets.QLabel(self.aesInOutVerticalLayoutWidget)
        self.aesOutputLabel.setObjectName("aesOutputLabel")
        self.aesInOutVerticalLayout.addWidget(self.aesOutputLabel)
        self.aesOutputTextEdit = QtWidgets.QTextEdit(self.aesInOutVerticalLayoutWidget)
        self.aesOutputTextEdit.setReadOnly(True)
        self.aesOutputTextEdit.setObjectName("aesOutputTextEdit")
        self.aesInOutVerticalLayout.addWidget(self.aesOutputTextEdit)

        # SHA Tab Widget
        self.shaTab = QtWidgets.QWidget()
        self.shaTab.setObjectName("shaTab")
        self.tabWidget.addTab(self.shaTab, "")

        # SHA Settings Group Box
        self.shaSettingsGroupBox = QtWidgets.QGroupBox(self.shaTab)
        self.shaSettingsGroupBox.setGeometry(QtCore.QRect(5, 4, 671, 88))
        self.shaSettingsGroupBox.setObjectName("shaSettingsGroupBox")

        # SHA Settings Radio Grid Layout
        self.shaRadioGridLayoutWidget = QtWidgets.QWidget(self.shaSettingsGroupBox)
        self.shaRadioGridLayoutWidget.setGeometry(QtCore.QRect(8, 14, 419, 70))
        self.shaRadioGridLayoutWidget.setObjectName("shaRadioGridLayoutWidget")
        self.shaRadioGridLayout = QtWidgets.QGridLayout(self.shaRadioGridLayoutWidget)
        self.shaRadioGridLayout.setContentsMargins(0, 0, 0, 0)
        self.shaRadioGridLayout.setObjectName("shaRadioGridLayout")

        # SHA Settings Method Radio Buttons Group
        self.shaMethodLabel = QtWidgets.QLabel(self.shaRadioGridLayoutWidget)
        self.shaMethodLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.shaMethodLabel.setObjectName("shaMethodLabel")
        self.shaRadioGridLayout.addWidget(self.shaMethodLabel, 0, 0, 1, 1)

        self.sha256RadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.sha256RadioBtn.setChecked(True)
        self.sha256RadioBtn.setObjectName("sha256RadioBtn")
        self.shaRadioGridLayout.addWidget(self.sha256RadioBtn, 0, 1, 1, 1)

        self.sha512RadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.sha512RadioBtn.setObjectName("sha512RadioBtn")
        self.shaRadioGridLayout.addWidget(self.sha512RadioBtn, 0, 2, 1, 1)

        self.sha3256RadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.sha3256RadioBtn.setObjectName("sha3256RadioBtn")
        self.shaRadioGridLayout.addWidget(self.sha3256RadioBtn, 0, 3, 1, 1)

        self.sha3512RadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.sha3512RadioBtn.setObjectName("sha3512RadioBtn")
        self.shaRadioGridLayout.addWidget(self.sha3512RadioBtn, 0, 4, 1, 1)

        self.shaMethodButtonGroup = QtWidgets.QButtonGroup(self)
        self.shaMethodButtonGroup.setObjectName("shaMethodButtonGroup")
        self.shaMethodButtonGroup.addButton(self.sha256RadioBtn)
        self.shaMethodButtonGroup.addButton(self.sha512RadioBtn)
        self.shaMethodButtonGroup.addButton(self.sha3256RadioBtn)
        self.shaMethodButtonGroup.addButton(self.sha3512RadioBtn)
        self.shaMethodButtonGroup.buttonToggled.connect(self.shaInputTextChanged)

        # SHA Settings Format Radio Buttons Group
        self.shaFormatLabel = QtWidgets.QLabel(self.shaRadioGridLayoutWidget)
        self.shaFormatLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.shaFormatLabel.setObjectName("shaFormatLabel")
        self.shaRadioGridLayout.addWidget(self.shaFormatLabel, 1, 0, 1, 1)

        self.shaHexRadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.shaHexRadioBtn.setChecked(True)
        self.shaHexRadioBtn.setObjectName("shaHexRadioBtn")
        self.shaHexRadioBtn.toggled.connect(self.shaInputTextChanged)
        self.shaRadioGridLayout.addWidget(self.shaHexRadioBtn, 1, 1, 1, 1)

        self.shaB64RadioBtn = QtWidgets.QRadioButton(self.shaRadioGridLayoutWidget)
        self.shaB64RadioBtn.setObjectName("shaB64RadioBtn")
        self.shaRadioGridLayout.addWidget(self.shaB64RadioBtn, 1, 2, 1, 1)

        self.shaFormatButtonGroup = QtWidgets.QButtonGroup(self)
        self.shaFormatButtonGroup.setObjectName("shaFormatButtonGroup")
        self.shaFormatButtonGroup.addButton(self.shaB64RadioBtn)
        self.shaFormatButtonGroup.addButton(self.shaHexRadioBtn)

        # SHA InOut Vertical Layout
        self.shaInOutVerticalLayoutWidget = QtWidgets.QWidget(self.shaTab)
        self.shaInOutVerticalLayoutWidget.setGeometry(QtCore.QRect(5, 99, 671, 253))
        self.shaInOutVerticalLayoutWidget.setObjectName("shaInOutVerticalLayoutWidget")
        self.shaInOutVerticalLayout = QtWidgets.QVBoxLayout(self.shaInOutVerticalLayoutWidget)
        self.shaInOutVerticalLayout.setContentsMargins(0, 0, 0, 0)
        self.shaInOutVerticalLayout.setObjectName("shaInOutVerticalLayout")

        # SHA Input Text Edit
        self.shaInputLabel = QtWidgets.QLabel(self.shaInOutVerticalLayoutWidget)
        self.shaInputLabel.setObjectName("shaInputLabel")
        self.shaInOutVerticalLayout.addWidget(self.shaInputLabel)
        self.shaInputTextEdit = QtWidgets.QTextEdit(self.shaInOutVerticalLayoutWidget)
        self.shaInputTextEdit.setObjectName("shaInputTextEdit")
        self.shaInputTextEdit.textChanged.connect(self.shaInputTextChanged)
        self.shaInOutVerticalLayout.addWidget(self.shaInputTextEdit)

        # SHA Output Text Edit
        self.shaOutputLabel = QtWidgets.QLabel(self.shaInOutVerticalLayoutWidget)
        self.shaOutputLabel.setObjectName("shaOutputLabel")
        self.shaInOutVerticalLayout.addWidget(self.shaOutputLabel)
        self.shaOutputTextEdit = QtWidgets.QTextEdit(self.shaInOutVerticalLayoutWidget)
        self.shaOutputTextEdit.setReadOnly(True)
        self.shaOutputTextEdit.setObjectName("shaOutputTextEdit")
        self.shaInOutVerticalLayout.addWidget(self.shaOutputTextEdit)

        # BASE64 Tab Widget
        self.b64Tab = QtWidgets.QWidget()
        self.b64Tab.setObjectName("b64Tab")
        self.tabWidget.addTab(self.b64Tab, "")

        # BASE64 Settings Group Box
        self.b64SettingsGroupBox = QtWidgets.QGroupBox(self.b64Tab)
        self.b64SettingsGroupBox.setGeometry(QtCore.QRect(5, 4, 671, 88))
        self.b64SettingsGroupBox.setObjectName("b64SettingsGroupBox")

        # BASE64 Settings Radio Grid Layout
        self.b64RadioGridLayoutWidget = QtWidgets.QWidget(self.b64SettingsGroupBox)
        self.b64RadioGridLayoutWidget.setGeometry(QtCore.QRect(8, 14, 249, 70))
        self.b64RadioGridLayoutWidget.setObjectName("b64RadioGridLayoutWidget")
        self.b64RadioGridLayout = QtWidgets.QGridLayout(self.b64RadioGridLayoutWidget)
        self.b64RadioGridLayout.setContentsMargins(0, 0, 0, 0)
        self.b64RadioGridLayout.setObjectName("b64RadioGridLayout")

        # BASE64 Settings Method Radio Buttons Group
        self.b64MethodLabel = QtWidgets.QLabel(self.b64RadioGridLayoutWidget)
        self.b64MethodLabel.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.b64MethodLabel.setObjectName("b64MethodLabel")
        self.b64RadioGridLayout.addWidget(self.b64MethodLabel, 0, 0, 1, 1)

        self.b64EncodingRadioBtn = QtWidgets.QRadioButton(self.b64RadioGridLayoutWidget)
        self.b64EncodingRadioBtn.setChecked(True)
        self.b64EncodingRadioBtn.setObjectName("b64EncodingRadioBtn")
        self.b64EncodingRadioBtn.toggled.connect(self.b64MethodRadioChanged)
        self.b64RadioGridLayout.addWidget(self.b64EncodingRadioBtn, 0, 1, 1, 1)

        self.b64DecodeRadioBtn = QtWidgets.QRadioButton(self.b64RadioGridLayoutWidget)
        self.b64DecodeRadioBtn.setObjectName("b64DecodeRadioBtn")
        self.b64RadioGridLayout.addWidget(self.b64DecodeRadioBtn, 0, 2, 1, 1)

        self.b64MethodButtonGroup = QtWidgets.QButtonGroup(self)
        self.b64MethodButtonGroup.setObjectName("b64MethodButtonGroup")
        self.b64MethodButtonGroup.addButton(self.b64EncodingRadioBtn)
        self.b64MethodButtonGroup.addButton(self.b64DecodeRadioBtn)

        # BASE64 InOut Vertical Layout
        self.b64InOutVerticalLayoutWidget = QtWidgets.QWidget(self.b64Tab)
        self.b64InOutVerticalLayoutWidget.setGeometry(QtCore.QRect(5, 99, 671, 253))
        self.b64InOutVerticalLayoutWidget.setObjectName("b64InOutVerticalLayoutWidget")
        self.b64InOutVerticalLayout = QtWidgets.QVBoxLayout(self.b64InOutVerticalLayoutWidget)
        self.b64InOutVerticalLayout.setContentsMargins(0, 0, 0, 0)
        self.b64InOutVerticalLayout.setObjectName("b64InOutVerticalLayout")

        # BASE64 Input Text Edit
        self.b64InputLabel = QtWidgets.QLabel(self.b64InOutVerticalLayoutWidget)
        self.b64InputLabel.setObjectName("b64InputLabel")
        self.b64InOutVerticalLayout.addWidget(self.b64InputLabel)
        self.b64InputTextEdit = QtWidgets.QTextEdit(self.b64InOutVerticalLayoutWidget)
        self.b64InputTextEdit.setObjectName("b64InputTextEdit")
        self.b64InputTextEdit.textChanged.connect(self.b64InputTextChanged)
        self.b64InOutVerticalLayout.addWidget(self.b64InputTextEdit)

        # BASE64 Output Text Edit
        self.b64OutputLabel = QtWidgets.QLabel(self.b64InOutVerticalLayoutWidget)
        self.b64OutputLabel.setObjectName("b64OutputLabel")
        self.b64InOutVerticalLayout.addWidget(self.b64OutputLabel)
        self.b64OutputTextEdit = QtWidgets.QTextEdit(self.b64InOutVerticalLayoutWidget)
        self.b64OutputTextEdit.setReadOnly(True)
        self.b64OutputTextEdit.setObjectName("b64OutputTextEdit")
        self.b64InOutVerticalLayout.addWidget(self.b64OutputTextEdit)

        self.retranslateUi()
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "TEXT ENCRYPTION/DECRYPTION CONVERTER"))
        self.aesSettingsGroupBox.setTitle(_translate("MainWindow", "Settings"))
        self.aesDescryptRadioBtn.setText(_translate("MainWindow", "Decryption"))
        self.aesEncryptRadioBtn.setText(_translate("MainWindow", "Encryption"))
        self.aesMethodLabel.setText(_translate("MainWindow", "Method"))
        self.aesFormatLabel.setText(_translate("MainWindow", "Format"))
        self.aesHexRadioBtn.setText(_translate("MainWindow", "Hex"))
        self.aesB64RadioBtn.setText(_translate("MainWindow", "Base64"))
        self.aesPasswordLabel.setText(_translate("MainWindow", "Password"))
        self.aesSaltLabel.setText(_translate("MainWindow", "Salt"))
        self.aesInputLabel.setText(_translate("MainWindow", "Input Text"))
        self.aesOutputLabel.setText(_translate("MainWindow", "Output Text"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.aesTab), _translate("MainWindow", "AES"))
        self.shaSettingsGroupBox.setTitle(_translate("MainWindow", "Settings"))
        self.sha256RadioBtn.setText(_translate("MainWindow", "SHA-256"))
        self.shaFormatLabel.setText(_translate("MainWindow", "Format"))
        self.shaB64RadioBtn.setText(_translate("MainWindow", "Base64"))
        self.sha3256RadioBtn.setText(_translate("MainWindow", "SHA3-256"))
        self.shaHexRadioBtn.setText(_translate("MainWindow", "Hex"))
        self.shaMethodLabel.setText(_translate("MainWindow", "Method"))
        self.sha512RadioBtn.setText(_translate("MainWindow", "SHA-512"))
        self.sha3512RadioBtn.setText(_translate("MainWindow", "SHA3-512"))
        self.shaInputLabel.setText(_translate("MainWindow", "Input Text"))
        self.shaOutputLabel.setText(_translate("MainWindow", "Output Text"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.shaTab), _translate("MainWindow", "SHA"))
        self.b64SettingsGroupBox.setTitle(_translate("MainWindow", "Settings"))
        self.b64EncodingRadioBtn.setText(_translate("MainWindow", "Encoding"))
        self.b64DecodeRadioBtn.setText(_translate("MainWindow", "Decoding"))
        self.b64MethodLabel.setText(_translate("MainWindow", "Method"))
        self.b64InputLabel.setText(_translate("MainWindow", "Input Text"))
        self.b64OutputLabel.setText(_translate("MainWindow", "Output Text"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.b64Tab), _translate("MainWindow", "BASE64"))

    def aesInputTextChanged(self, *args):
        if bool(self.aesInputTextEdit.toPlainText().strip()):
            try:
                text = self.aesInputTextEdit.toPlainText().strip()
                password = self.aesPasswordLineEdit.text().strip() if bool(self.aesPasswordLineEdit.text().strip()) else AES_DEFAULT_PASSWORD
                salt = self.aesSaltLineEdit.text().strip() if bool(self.aesSaltLineEdit.text().strip()) else AES_DEFAULT_SALT
                format = OUTPUT_FORMAT.HEX if self.aesHexRadioBtn.isChecked() else OUTPUT_FORMAT.B64
                self.aesOutputTextEdit.setText(self.aes.encrypt(text, password, salt, format) if self.aesEncryptRadioBtn.isChecked() else self.aes.decrypt(text, password, salt, format))
            except Exception as e:
                self.aesOutputTextEdit.setText(str(e))

    def aesMethodRadioChanged(self, *args):
        if bool(self.aesOutputTextEdit.toPlainText().strip()):
            self.aesInputTextEdit.setText(self.aesOutputTextEdit.toPlainText().strip())

    def aesFormatRadioChanged(self, *args):
        if bool(self.aesInputTextEdit.toPlainText().strip()) and self.aesDescryptRadioBtn.isChecked():
            text = self.b64.hexToB64(self.aesInputTextEdit.toPlainText().strip()) if self.aesB64RadioBtn.isChecked() else self.b64.b64ToHex(self.aesInputTextEdit.toPlainText().strip())
            self.aesInputTextEdit.setText(text)
        else:
            self.aesInputTextChanged(args)

    def shaInputTextChanged(self, *args):
        if bool(self.shaInputTextEdit.toPlainText().strip()):
            try:
                text = self.shaInputTextEdit.toPlainText().strip()
                algorithm = SHA_ALGORITHM(self.shaMethodButtonGroup.checkedButton().text().replace('-', '_').lower())
                format = OUTPUT_FORMAT.HEX if self.shaHexRadioBtn.isChecked() else OUTPUT_FORMAT.B64
                self.shaOutputTextEdit.setText(self.sha.hash(text, algorithm, format))
            except Exception as e:
                self.shaOutputTextEdit.setText(str(e))

    def b64InputTextChanged(self, *args):
        if bool(self.b64InputTextEdit.toPlainText().strip()):
            try:
                text = self.b64InputTextEdit.toPlainText().strip()
                self.b64OutputTextEdit.setText(self.b64.encode(text) if self.b64EncodingRadioBtn.isChecked() else self.b64.decode(text))
            except Exception as e:
                self.b64OutputTextEdit.setText(str(e))

    def b64MethodRadioChanged(self, *args):
        if bool(self.b64OutputTextEdit.toPlainText().strip()):
            self.b64InputTextEdit.setText(self.b64OutputTextEdit.toPlainText().strip())