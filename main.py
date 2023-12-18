import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.uic import loadUi
from utils.client import *
import bcrypt

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
        
    def switch_to_login(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.login_page)
            
    def switch_to_signup(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.signup_page)
        
    
if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())