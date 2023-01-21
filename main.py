import sys
import stem
from PyQt5.QtCore import QUrl
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyBlocking import PyBlocking
from google.cloud import safebrowsing
import execjs
from concurrent.futures import ThreadPoolExecutor
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from PyQt5.QtGui import QIcon
from cryptography.fernet import Fernet
        
app = QApplication(sys.argv)
window = QMainWindow()
view = QWebEngineView()

class Browser(QtWebEngineWidgets.QWebEngineView):
    def __init__(self):
        def execute_code(code):
            # Create a new sandbox
            sb = Sandbox()
            # Execute the code within the sandbox
            result = sb.execute(code)
            # Check the result for errors
            if result.error:
                print(result.error)
            else:
                print(result.output)
 
        super().__init__()
        self.setWindowTitle("Atomic Browser")
        self.setWindowIcon(QIcon("path/to/logo.png"))
        from sandbox import Sandbox


        self.ctx = execjs.compile("""
            var V8 = require("v8");
            function executeJS(javascript) {
                return V8.eval(javascript);
            }
        """)

            def encrypt_settings(self, settings_data):
                # Serialize the settings data
                data = json.dumps(settings_data)
                # Encrypt the data
                encrypted_data = self.cipher.encrypt(data.encode())
                # Store the encrypted data
                with open("settings.bin", "wb") as f:
                    f.write(encrypted_data)

            def decrypt_settings(self):
                # Load the encrypted data
                with open("settings.bin", "rb") as f:
                    encrypted_data = f.read()
                # Decrypt the data
                data = self.cipher.decrypt(encrypted_data).decode()
                # Deserialize the data
                settings_data = json.loads(data)
                return settings_data


        # History tab close / clear etc
        self.history_tab = QtWidgets.QTabWidget()
        self.history_tab.setTabPosition(QtWidgets.QTabWidget.West)
        self.history_tab.setMovable(True)
        self.history_tab.setTabsClosable(True)
        self.history_tab.tabCloseRequested.connect(self.history_tab.removeTab)
        self.history_tab.setVisible(False)
        self.add_history_tab()
    # Adds the history tab    
    def add_history_tab(self):
        self.history_tab.addTab(HistoryTab(self.history()), "History")
        self.history_tab.setCurrentIndex(self.history_tab.count() - 1)
    # Lets the user toggle the history tab    
    def toggle_history_tab(self):
        if self.history_tab.isVisible():
            self.history_tab.setVisible(False)
        else:
            self.history_tab.setVisible(True)
            
    # Creates a toolbar with a back button, forward button, and home button        
    def create_toolbar(self):
        self.toolbar = self.addToolBar("Navigation")

        # Create the back button
        self.back_button = QtWidgets.QAction(QIcon("path/to/back_icon.png"), "Back", self)
        self.back_button.triggered.connect(self.back)
        self.toolbar.addAction(self.back_button)

        # Create the forward button
        self.forward_button = QtWidgets.QAction(QIcon("path/to/forward_icon.png"), "Forward", self)
        self.forward_button.triggered.connect(self.forward)
        self.toolbar.addAction(self.forward_button)

        # Create the home button
        self.home_button = QtWidgets.QAction(QIcon("path/to/home_icon.png"), "Home", self)
        self.home_button.triggered.connect(self.home)
        self.toolbar.addAction(self.home_button)

    def back(self):
        self.history().back()

    def forward(self):
        self.history().forward()

    def home(self):
        self.load(QUrl(self.home_url))

    def clear_history(self):
        self.history().clear()
        self.history_tab.clear()

# Creates the history tab on the GUI and adds users browsing history to the GUI tab            
class HistoryTab(QtWidgets.QWidget):
    def __init__(self, history, parent=None):
        super().__init__(parent)

        # Create a list widget to display the history
        self.history_list = QtWidgets.QListWidget()
        self.history_list.setAlternatingRowColors(True)

        # Populate the list widget with the browsing history
        for url in history:
            item = QtWidgets.QListWidgetItem(url)
            self.history_list.addItem(item)

        # Create a clear button
        clear_button = QtWidgets.QPushButton("Clear History")
        clear_button.clicked.connect(self.clear_history)

        # Create a layout to hold the list widget and the clear button
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.history_list)
        layout.addWidget(clear_button)

        self.setLayout(layout)
        
        # Enable memory caching (Makes browser faster)
        self.settings().setAttribute(QtWebEngineWidgets.QWebEngineSettings.LocalStorageEnabled, True)
        # Set the cache size
        self.profile().setHttpCacheMaximumSize(1024 * 1024 * 100) # 100MB
        self.manager = QNetworkAccessManager()
        self.manager.sslErrors.connect(self.handle_ssl_errors)
        self.profile().setNetworkAccessManager(self.manager)
        # ssl error handler
        self.sslErrors.connect(self.sslErrorHandler)

    def sslErrorHandler(self, reply, errors):
        for error in errors:
            # Get the certificate for the error
            cert = error.certificate()
            # Check the certificate's expiry date
            if cert.expiryDate() < QDateTime.currentDateTime():
                # Certificate has expired
                print("Error: Certificate has expired.")
            else:
                # Check the certificate's subject and issuer
                subject = cert.subjectInfo(QSslCertificate.CommonName)
                issuer = cert.issuerInfo(QSslCertificate.CommonName)
                if subject != "example.com" or issuer != "Example CA":
                    # Certificate is not valid
                    print("Error: Invalid certificate.")
                else:
                    # Certificate is valid
                    print("Certificate is valid.")

    def load(self, url):
        if url.scheme() != 'https':
            url.setScheme('https')
        super().load(url)
    def create_trust_store(self):
        trust_store = set()
        # Add root CA certificates to trust store
        trust_store.add(x509.load_pem_x509_certificate(root_ca_pem_data, default_backend()))
        return trust_store
    def validate_certificate(self, certificate):
        # Extract root CA certificate from chain
        root_ca_cert = certificate.get_extension_for_class(x509.SubjectKeyIdentifier).value
        # Check if root CA is in trust store
        if root_ca_cert not in self.trust_store:
            return False
        return True
    def ssl_errors(self, reply, errors):
        for error in errors:
            if isinstance(error, ssl.CertificateError):
                # Extract certificate chain from error
                certificate = error.certificate
                if not self.validate_certificate(certificate):
                    # Reject connection if certificate is not trusted
                    reply.ignoreSslErrors()

         # Create a tab for uploading trusted certificates
        self.certificate_tab = QtWidgets.QWidget()
        self.certificate_tab.setLayout(QtWidgets.QVBoxLayout())
        self.addTab(self.certificate_tab, "Trusted Certificates")

        # Create a file dialog for selecting the certificate file
        self.file_dialog = QtWidgets.QFileDialog(self)
        self.file_dialog.setNameFilter("Certificate files (*.crt, *.pem)")

        # Create a button for opening the file dialog
        self.upload_button = QtWidgets.QPushButton("Upload Certificate")
        self.upload_button.clicked.connect(self.upload_certificate)
        self.certificate_tab.layout().addWidget(self.upload_button)

        # Create a list widget for displaying the uploaded certificates
        self.certificate_list = QtWidgets.QListWidget()
        self.certificate_tab.layout().addWidget(self.certificate_list)
        
        def upload_certificates(self, path):
            try:
                # Open the file specified by the user
                with open(path, "rb") as cert_file:
                    # Read the certificate data
                    cert_data = cert_file.read()
                    # Load the certificate using the cryptography library
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    # Verify that the certificate is valid and has not expired
                    cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                    # Add the certificate to the browser's trust store
                    self.profile().setTrustedCertificates(
                        [cert_data],
                        QWebEngineClientCertificateStore.Pem
                    )
                    print("Certificate uploaded successfully")
            except Exception as e:
                def check_certificate(self, url):
                    certificate = self.get_certificate(url)
                    if not certificate.is_valid():
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)
                        msg.setText("Invalid certificate detected")
                        msg.setInformativeText("The website's certificate is not valid. Do you want to continue anyway?")
                        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                        msg.setDefaultButton(QMessageBox.No)
                        retval = msg.exec_()
                        if retval == QMessageBox.Yes:
                            self.load(QUrl(url))
                        else:
                            self.load(QUrl("https://www.google.com"))
                    else:
                        self.load(QUrl(url))
                            browser = Browser()
                            browser.upload_certificates("path/to/certificate.pem")

        # Initialize SafeBrowsing
        self.safe_browsing = SafeBrowsing("API_KEY")
    # Use JV8 to load JS (Makes browser faster)
    def executeJS(self, javascript):
        return self.ctx.call("executeJS", javascript)
    # loads multiple items into HTTP request (Makes browser faster)
    def load_urls(self, urls):
        futures = [self.executor.submit(self.load, QUrl(url)) for url in urls]
        for future in futures:
            future.result()
    def load(self, url):
        # Check the URL against the Google Safe Browsing API
        safe_check = self.safe_browsing.check_url(url)
        if safe_check != "URL is safe":
            print(safe_check)
            return
        # Load the URL if it is safe
        super().load(url)

        # Create a button for the private window
        self.private_button = QtWidgets.QPushButton("Private Window", self)
        self.private_button.clicked.connect(self.private_window)
        self.private_button.setShortcut("Ctrl+Shift+N")
        self.private_button.setToolTip("Open a new private window using Tor")
        self.addToolBar(QtCore.Qt.RightToolBarArea, self.private_button)

    def private_window(self):
        # Start the Tor controller
        controller = stem.control.Controller.from_port(port = 9051)
        controller.authenticate()

        # Get a new identity
        controller.signal(stem.Signal.NEWNYM)

        # Create a new QWebEngineView with the private profile
        private_view = QWebEngineView(self.private_profile, self)
        private_view.setUrl(QUrl("https://check.torproject.org"))
        private_view.setWindowTitle("Atomic Browser - Private Window")
        private_view.setWindowIcon(QtGui.QIcon("path/to/logo.png"))
        private_view.show()
        

# Initialize the PyBlocking object
blocking = PyBlocking()

# Block ads and trackers
blocking.block_ads()
blocking.block_trackers()

# Connect the PyBlocking object to the web engine
view.page().profile().setRequestInterceptor(blocking)

# Create a dictionary to store bookmarks
bookmarks = {}

# Create a menu to hold the bookmarks
bookmark_menu = QMenu("Bookmarks")

# Add the bookmark menu to the main window
window.menuBar().addMenu(bookmark_menu)

# Connect the 'loadFinished' signal to a slot
view.loadFinished.connect(load_finished)

# Define a slot function to add a bookmark
def add_bookmark():
    url = view.url().toString()
    title = view.title()
    bookmarks[title] = url
    # Create a new action for the bookmark
    bookmark_action = QAction(title, view)
    # Connect the action to a slot function
    bookmark_action.triggered.connect(lambda: view.load(QUrl(bookmarks[title])))
    # Add the action to the bookmark menu
    bookmark_menu.addAction(bookmark_action)

# Add a 'Add Bookmark' action to the main window
add_bookmark_action = QAction("Add Bookmark", view)
add_bookmark_action.triggered.connect(add_bookmark)
window.addAction(add_bookmark_action)

class GlobalSettings:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        settings = QWebEngineSettings.globalSettings()
        settings.setAttribute(QWebEngineSettings.AutoLoadIconsForPage, True)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.SpatialNavigationEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.HyperlinkAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.AutoLoadIconsForPage, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanCloseWindows, True)
        settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, True)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.ShowScrollBars, True)
        settings.setAttribute(QWebEngineSettings.WebSecurityEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, True)
        settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, True)


if __name__ == "__main__":
    # Create an instance of the Browser class
    browser = Browser()
    # Encrypt the global settings using the cryptography library
    encrypt_settings(browser.settings)
    # Create a sandbox environment using the python-sandbox library
    create_sandbox(browser)

    # Initialize the SSL/TLS certificate validation and pinning
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile='path/to/trusted_certificates.pem')
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations('path/to/trusted_certificates.pem')
    ssl_context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
    QSslConfiguration.setDefaultConfiguration(ssl_context)

    app = QtWidgets.QApplication(sys.argv)
    browser = Browser("YOUR_API_KEY")
    browser.show()
    browser.load_urls(["https://www.google.com"])
    sys.exit(app.exec_())
