import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QMessageBox, QFrame, QVBoxLayout, QPushButton, QLabel, QInputDialog, QMenu, QDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.uic import loadUi
from utils.client import *
import bcrypt
import uuid

class AuthenticationManager:
    @staticmethod
    def signup(email, password, full_name):
        try:
            response = supabase.auth.sign_up({
                'email': email,
                'password': password,
                'options' : {
                    'data' : {
                        'name': full_name
                    }
                }
            })
            
            if response:
                user_data = {
                    'uid': response.user.id,
                    'full_name': full_name,
                    'email': email,
                    'password': AuthenticationManager.hash_password(password).decode('utf8'),
                }
                
                supabase.table('users').insert([user_data]).execute()
                
                AuthenticationManager.show_popup('Success', 'Sign up successful!')
                global userId
                userId = response.user.id
                global username
                username = response.user.user_metadata.get('name').split(" ")[0]
                
            print('Sign up successful')
            return response
        except Exception as e:
            print(f'An error occurred during signup: {e}')
            
    @staticmethod
    def login(email, password):
        try:
            response = supabase.auth.sign_in_with_password({
                'email': email,
                'password': password
            })       
            
            print('Login successful')
            AuthenticationManager.show_popup('Success', 'Login successful!')
            global userId
            userId = response.user.id
            global username
            username = response.user.user_metadata.get('name').split(" ")[0]
            
            return response
        except Exception as e:
            print(f'An error occurred during login: {e}')
    @staticmethod        
    def logout():
        try:
            response = supabase.auth.sign_out()
            print("Logout successful!")
            AuthenticationManager.show_popup("Logout Successful", "User logged out.")
            return response
        except Exception as e:
            print(f"An error occurred during logout: {e}")
            
    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed
    
    @staticmethod
    def show_popup(title, message):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.stacked_widget = QStackedWidget()

        self.login_page = loadUi('ui/login.ui')
        self.home_page = loadUi('ui/home.ui')
        self.navbar = loadUi('ui/navbar.ui')
        self.signup_page = loadUi('ui/signup.ui')

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.home_page)
        self.stacked_widget.addWidget(self.navbar)
        self.stacked_widget.addWidget(self.signup_page)

        self.setCentralWidget(self.stacked_widget)

        self.auth_manager = AuthenticationManager()
        
        self.login_page.signUpLabel.mousePressEvent = self.switch_to_signup
        self.signup_page.logInLabel.mousePressEvent = self.switch_to_login
        
        self.signup_page.pushButtonEmail.clicked.connect(self.signup)
        self.login_page.pushButtonEmail.clicked.connect(self.login)
        self.home_page.pushButtonLogout.clicked.connect(self.logout)
        

    def signup(self):
        full_name = self.signup_page.lineEditFullName.text()
        email = self.signup_page.lineEditEmail.text()
        password = self.signup_page.lineEditPassword.text()
        
        response = self.auth_manager.signup(email, password, full_name)
        
        if response:
            self.switch_to_home()
            
    def login(self):
        email = self.login_page.lineEditEmail.text()
        password = self.login_page.lineEditPassword.text()
        
        response = self.auth_manager.login(email, password)
        
        if response:
            self.switch_to_home()
            
    def switch_to_home(self):
        self.stacked_widget.setCurrentWidget(self.home_page)
        self.home_page.label_4.setText(f"Hi {username}!")
        self.update_ui()
        
    def generate_doc_id():
        doc_id = str(uuid.uuid4())
        return doc_id
    
    def create_doc(self):
        new_doc_id = self.generate_doc_id()
        doc_name, ok = QInputDialog.getText(self, "New Document", "Enter document name:")
        if doc_name and ok:
            uuids = supabase.table('users').select('docs').eq('uid', userId).execute().data[0]['docs']
            print(f'Existing uuids: {uuids}')
            if uuids is None:
                uuids = [new_doc_id]
            else:
                uuids.append(new_doc_id)
            print(f'New uuids: {uuids}')
            supabase.table('users').update({'docs': uuids}).eq('uid', userId).execute()
            global docId
            docId = new_doc_id
            supabase.table('docs').insert([{'uuid': new_doc_id, 'name': doc_name, 'content': ''}]).execute()
            self.update_ui()
            self.switch_to_navbar(doc_name)
            
    def fetch_docs(self):
        try:
            docs_data = supabase.table('docs').select('name').contains('users', [userId]).execute().data
            
            return [doc['name'] for doc in docs_data] if docs_data else []
        except Exception as e:
            print(f'An error occurred during fetch_docs: {e}')
            return []
    
    def update_ui(self):
        for i in reversed(range(self.home_page.horizontalLayoutDocs.count())):
            self.home_page.horizontalLayoutDocs.itemAt(i).widget().setParent(None)
        
        doc_names = self.fetch_docs()
        print(f'Fetched Doc names: {doc_names}')
        
        for doc_name in doc_names:
            doc_widget = self.create_doc_widget(doc_name)
            self.home_page.horizontalLayoutDocs.addWidget(doc_widget)
            
    def create_doc_widget(self, doc_name):
        doc_frame = QFrame()
        doc_frame.setStyleSheet("background-color: white; border-radius: 10px;")
        doc_frame.setFixedHeight(300)
        doc_frame.setFixedWidth(220)
        doc_button = QPushButton(doc_name)
        doc_button.setStyleSheet("background-color: #32CC70; border-radius:20px;")
        doc_button.setFixedHeight(50)
        doc_button.clicked.connect(lambda _, name=doc_name: self.open_doc(name))
        
        frame_layout = QVBoxLayout()
        
        doc_label = QLabel()
        pixmap = QPixmap("resources/images/docs.png")
        doc_label.setPixmap(pixmap)
        doc_label.setFixedHeight(150)
        doc_label.setScaledContents(True)
        doc_label.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(doc_label)
        
        frame_layout.addSpacing(10)
        
        frame_layout.addWidget(doc_button)
        doc_frame.setLayout(frame_layout)
        
        return doc_frame
    
    def open_doc(self, doc_name):
        global docId
        docId = supabase.table('docs').select('doc_id').eq('name', doc_name).execute().data[0]['doc_id']
        access_type = supabase.table('docs').select('access').eq('doc_id', docId).execute().data[0]['access']
        user_access = supabase.table('docs').select('user_access').eq('doc_id', docId).execute().data[0]['user_access']
        user_uuids = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
        
        if (userId!=user_uuids[0] and access_type=='Restricted') and (user_access[userId] == 'Restricted'):
            AuthenticationManager.show_popup("Access Denied", "You do not have access to this document.")
        else:
            self.switch_to_navbar(doc_name)
            
    def switch_to_navbar(self, doc_name):
        self.stacked_widget.setCurrentWidget(self.navbar)
        self.navbar.pushButton_6.setText(f"Hi {username}!")
        global docName
        docName = doc_name
        self.update_text_edit()
        
    def update_text_edit(self):
        user_uuids = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
        if (userId in user_uuids):
            if userId == user_uuids[0]:
                initial_data = supabase.table('docs').select('content').eq('doc_id', docId).execute().data[0]['content']
                print(f'Initial data: {initial_data}')
                self.navbar.textEdit.setText(initial_data)
                self.navbar.textEdit.setReadOnly(False)
                self.navbar.menuBar().setEnabled(True)
                self.navbar.menuBar().findChild(QMenu, 'menuAccess').setEnabled(True)
            else:
                user_access = supabase.table('docs').select('user_access').eq('doc_id', docId).execute().data[0]['user_access']
                access_type = user_access[userId]
                if access_type == 'Restricted':
                    AuthenticationManager.show_popup("Access Denied", "You do not have access to this document.")
                    if userId: user_uuids.remove(userId)
                    supabase.table('docs').update({'users': user_uuids}).eq('doc_id', docId).execute()
                    self.switch_to_home()
                elif access_type == 'Reader':
                    self.navbar.textEdit.setReadOnly(True)
                    AuthenticationManager.show_popup("Access Granted", "You have read-only access to this document.")
                elif access_type == 'Writer':
                    self.navbar.textEdit.setReadOnly(False)
                    AuthenticationManager.show_popup("Access Granted", "You have read-write access to this document.")
                self.navbar.menuBar().findChild(QMenu, 'menuAccess').setEnabled(False)
                
                
    def switch_to_login(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.login_page)
            
    def switch_to_signup(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.signup_page)
        
    def logout(self):
        self.auth_manager.logout()
        self.stacked_widget.setCurrentWidget(self.login_page)
    
    
if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())