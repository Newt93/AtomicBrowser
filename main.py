import sys
import stem
from PyQt5.QtCore import QUrl
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyBlocking import PyBlocking
from google.cloud import safebrowsing
import execjs
from concurrent.futures import ThreadPoolExecutor


app = QApplication(sys.argv)
window = QMainWindow()
view = QWebEngineView()

from PyQt5.QtGui import QIcon

class Browser(QtWebEngineWidgets.QWebEngineView):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Atomic Browser")
        self.setWindowIcon(QIcon("path/to/logo.png"))
        self.ctx = execjs.compile("""
            var V8 = require("v8");
            function executeJS(javascript) {
                return V8.eval(javascript);
            }
        """)
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


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    browser = Browser("YOUR_API_KEY")
    browser.show()
    browser.load_urls(["https://www.google.com"])
    sys.exit(app.exec_())



