import sys, os
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QMessageBox, QFrame, QVBoxLayout, QPushButton, QLabel, QInputDialog, QMenu, QDialog, QWidget, QHBoxLayout, QTextEdit, QFileDialog, QSpinBox, QLineEdit, QTextBrowser
from PyQt5.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot, QTimer, QUrl
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtGui import QPixmap, QIcon, QTextDocument, QTextImageFormat, QDesktopServices, QFont
from PyQt5.uic import loadUi
from utils.client import *
from utils.credentials import google_password, google_username
import bcrypt
import uuid
import smtplib
from email.mime.text import MIMEText
import socket

from cloudinary_credentials import *
import cloudinary.uploader
import requests

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
class ImageSizeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.width_label = QLabel("Width:")
        self.height_label = QLabel("Height:")
        self.width_spinbox = QSpinBox()
        self.height_spinbox = QSpinBox()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(self.width_label)
        layout.addWidget(self.width_spinbox)
        layout.addWidget(self.height_label)
        layout.addWidget(self.height_spinbox)
        layout.addWidget(self.ok_button)
        layout.addWidget(self.cancel_button)
        
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        self.setLayout(layout)
        
    def get_image_size(self):
        result = self.exec_()
        if result == QDialog.Accepted:
            return self.width_spinbox.value(), self.height_spinbox.value()
        else:
            return None, None
        
           
class ImageHandler:
    def __init__(self, main_window):
        self.main_window = main_window
        
    def add_image(self):
        try:
            self.main_window.sync_timer.stop()
            file_dialog = QFileDialog()
            image_path, _ = file_dialog.getOpenFileName(self.main_window, "Select Image", "",  "Images (*.png *.xpm *.jpg *jpeg *.bmp)")
            
            if image_path:
                size_dialog = ImageSizeDialog(self.main_window)
                width, height = size_dialog.get_image_size()
                
                if width and height:
                    image_name = image_path.split('/')[-1][:-4]
                    upload_result = cloudinary.uploader.upload(image_path, public_id=image_name)
                    
                    if 'secure_url' in upload_result:
                        hosted_url = upload_result['secure_url']
                        print(f'Hosted URL: {hosted_url}')
                        
                        desktop_path = os.path.join(os.path.expanduser('~'), "Desktop")
                        
                        images_folder = os.path.join(desktop_path, "Docify", "Images")
                        os.makedirs(images_folder, exist_ok=True)
                        
                        local_path = os.path.join(images_folder, f"{image_name}.png")
                        
                        response = requests.get(hosted_url, stream=True)
                        with open(local_path, 'wb') as file:
                            for chunk in response.iter_content(chunk_size=128):
                                file.write(chunk)
                                
                        image_format = QTextImageFormat()
                        image_format.setWidth(width)
                        image_format.setHeight(height)
                        image_format.setName(local_path)
                        
                        cursor = self.main_window.text_edit.textCursor()
                        cursor.insertImage(image_format) 
        except Exception as e:
            print(f'An error occurred during add_image: {e}')
        finally:
            self.main_window.sync_timer.start()
class ShareDialog(QDialog):
    def __init__(self, doc_name):
        super(ShareDialog, self).__init__()
        loadUi('ui/share.ui', self)
        self.doc_name = doc_name
        doc_id = supabase.table('docs').select('doc_id').eq('name', doc_name).execute().data[0]['doc_id']
        self.doc_id = doc_id
        self.setWindowTitle(f"Share {doc_name}")
        
        self.update_user_list()
        self.pushButtonCopy.clicked.connect(MainWindow.copy_access_link)
        self.pushButtonDone.clicked.connect(self.get_share_info)
        
    def update_user_list(self):
        user_uuids = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
        
        for i in reversed(range(self.verticalLayout.count())): 
            self.verticalLayout.itemAt(i).widget().setParent(None)
            
        for idx, user_uuid in enumerate(user_uuids):
            user_widget = self.create_user_widget(user_uuid, idx == 0)
            self.verticalLayout.addWidget(user_widget)
        
    def create_user_widget(self, user_uuid, is_owner):
        user_name = self.get_user_name(user_uuid)
        profile_picture_path = "resources/images/user.png"
        
        user_widget = QWidget()
        user_layout = QHBoxLayout()
        
        profile_picture_label = QLabel()
        pixmap = QPixmap(profile_picture_path)
        profile_picture_label.setPixmap(pixmap)
        profile_picture_label.setFixedHeight(20)
        profile_picture_label.setFixedWidth(20)
        profile_picture_label.setScaledContents(True)
        
        user_name_label = QLabel(f"{username} (Owner)" if is_owner else user_name)
        
        user_layout.addWidget(profile_picture_label)
        user_layout.addWidget(user_name_label)
        
        user_widget.setLayout(user_layout)
        
        return user_widget                        
        
    def get_user_name(self, user_uuid):
        user_name = supabase.table('users').select('full_name').eq('uid', user_uuid).execute().data[0]['full_name']
        return user_name
    
    def get_share_info(self):
        email = self.lineEdit.text()
        access_type = self.comboBox.currentText()
        if email and access_type:
            self.grant_access(email, access_type, self.doc_id)
            if access_type == "Readable":
                access_type = "read"
            elif access_type == "Writable":
                access_type = "write"
            access_link = MainWindow.generate_general_access_link(self, self.doc_id, access_type)
            self.send_email(email, self.doc_name, access_link)
    
    def grant_access(self, email, access_type, doc_id):
        try:
            # Fetch user ID from the users table based on the provided email
            user_id_query = supabase.table('users').select('uid').eq('email', email).execute()
            user_id = user_id_query.data[0]['uid'] if user_id_query and user_id_query.data else None
                
            if user_id:
                # Update the docs table with the new user and access information
                current_users_query = supabase.table('docs').select('users').eq('doc_id', doc_id).execute()
                current_users = current_users_query.data[0]['users'] if current_users_query and current_users_query.data else []
                    
                # Add the new user and access information
                if user_id not in current_users: current_users.append(user_id)
                user_access_query = supabase.table('docs').select('user_access').eq('doc_id', doc_id).execute()
                current_user_access = user_access_query.data[0]['user_access'] if user_access_query and user_access_query.data else {}
                current_user_access[user_id] = access_type
                # user_access = {user_id: access_type}

                if access_type == "Restricted":
                    current_users.remove(user_id)
                    
                # Update the docs table
                supabase.table('docs').update({'users': current_users}).eq('doc_id', doc_id).execute()
                supabase.table('docs').update({'user_access': current_user_access}).eq('doc_id', doc_id).execute()
                self.update_user_list()
                # MainWindow.update_text_edit(self=MainWindow)

                if (access_type == "Restricted"):
                    print(f"Access revoked for {email}")
                    AuthenticationManager.show_popup("Access Revoked", f"Access revoked for {email}")
                    
                else:
                    print(f"Access granted to {email}")

            else:
                print("User not found.")
            

        except Exception as e:
            print(f"An error occurred: {e}")
     
    def send_email(self, to_email, doc_name, access_link):
        try:
            if str(access_link).endswith("Restricted"): 
                return
            # Set up your email server and credentials
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587  # Update with the appropriate port
            smtp_username = google_username
            smtp_password = google_password
            
            # Set up the message
            subject = f"Access to Document: {doc_name}"
            content = f"You have been granted access. Copy the link below to access the document:\n\n{access_link}"
            sender_email = supabase.table('users').select('email').eq('uid', userId).execute().data[0]['email']
            print(f"\nSender Email: {sender_email}")
            
            message = MIMEText(content)
            message['Subject'] = subject
            message['From'] = sender_email
            message['To'] = to_email

            # Connect to the SMTP server and send the email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()  # Use this line if your server requires TLS
                server.login(smtp_username, smtp_password)
                server.sendmail(sender_email, to_email, message.as_string())
                
            print(f"Email sent to {to_email}")

            AuthenticationManager.show_popup("Email Sent",f"Email sent to {to_email}")
        except Exception as e:
            print(f"An error occurred: {e}")
            AuthenticationManager.show_popup("Error", f"An error occurred: {e}")
            
class MyTextEdit(QTextEdit):
    def __init__(self, server_socket):
        super().__init__()
        
        self.server_socket = server_socket
        self.cursorPositionChanged.connect(self.send_data)
        
    def send_data(self):
        try:
            html = self.toHtml()
            
            supabase.table('docs').update({'content': html}).eq('doc_id', docId).execute()
            
            if not self.server_socket or self.server_socket.fileno() == -1:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.connect(('127.0.0.1', 5555))
                
            QMetaObject.invokeMethod(self, "send_to_server", Qt.QueuedConnection, Q_ARG(str, html))
        except Exception as e:
            print(f'An error occurred during send_data: {e}')
            
    @pyqtSlot(str)
    def send_to_server(self, html):
        self.server_socket.sendall(html.encode('utf-8'))
        
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
        self.image_handler = ImageHandler(self)
        
        self.login_page.signUpLabel.mousePressEvent = self.switch_to_signup
        self.signup_page.logInLabel.mousePressEvent = self.switch_to_login
        
        self.signup_page.pushButtonEmail.clicked.connect(self.signup)
        self.login_page.pushButtonEmail.clicked.connect(self.login)
        self.home_page.pushButtonLogout.clicked.connect(self.logout)
        
        self.home_page.pushButtonRefresh.clicked.connect(self.update_ui)
        self.home_page.pushButton.clicked.connect(self.create_doc)
        self.home_page.pushButtonAccess.clicked.connect(self.handle_access_link)
        self.navbar.actionRestricted.triggered.connect(lambda: self.update_access('Restricted'))
        self.navbar.actionReadable.triggered.connect(lambda: self.update_access('Readable'))
        self.navbar.actionWritable_3.triggered.connect(lambda: self.update_access('Writable'))
        self.navbar.pushButtonBack.clicked.connect(self.switch_to_home)
        self.navbar.pushButtonShare.clicked.connect(lambda: self.open_share_dialog(docName))
        self.navbar.pushButton.clicked.connect(self.make_bold)
        self.navbar.pushButton_2.clicked.connect(self.make_italic)
        self.navbar.pushButton_3.clicked.connect(self.make_underline)
        self.navbar.pushButtonColour.clicked.connect(self.change_colour)
        self.navbar.pushButtonFont.clicked.connect(self.change_font)

        existing_text_edit = self.navbar.textEdit
        self.navbar.verticalLayout.removeWidget(existing_text_edit)
        existing_text_edit.setParent(None)
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect(('127.0.0.1', 5555))
        
        self.text_edit = MyTextEdit(self.server_socket)
        self.navbar.verticalLayout.addWidget(self.text_edit)
        
        self.navbar.actionLink.triggered.connect(self.insert_link)
        self.navbar.pushButtonLink.clicked.connect(self.fetch_clickable_links)
        
        self.navbar.actionConvert_to_PDF.triggered.connect(self.convert_to_pdf)
        self.navbar.actionImage.triggered.connect(self.add_image)
        
    def add_image(self):
        self.sync_timer.stop()
        self.image_handler.add_image()
        self.sync_timer.start()
        
    def insert_link(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Insert Link")
        label_original = QLabel("Original Text:")
        original_text_input = QLineEdit()
        
        label_link = QLabel("Link:")
        link_input = QLineEdit()
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(lambda: self.update_link(original_text_input.text(), link_input.text(), dialog))
        
        layout = QVBoxLayout()
        layout.addWidget(label_original)
        layout.addWidget(original_text_input)
        layout.addWidget(label_link)
        layout.addWidget(link_input)
        layout.addWidget(ok_button)
        
        dialog.setLayout(layout)
        
        dialog.exec_()
        
    def update_link(self, original_text, link, dialog):
        try:
            cursor = self.text_edit.textCursor()
            cursor_position = cursor.position()
            
            cursor.insertHtml(f'<a href="{link}">{original_text}</a>')
            
            new_cursor_position = cursor_position + len(f'<a href="{link}">{original_text}</a>')
            cursor.setPosition(new_cursor_position)
            
            self.text_edit.setTextCursor(cursor)
            
            links_data = supabase.table('docs').select('links').eq('doc_id', docId).execute().data
            current_links = links_data[0]['links'] if links_data else {}
            current_links[original_text] = link
            supabase.table('docs').update({'links': current_links}).eq('doc_id', docId).execute()
            dialog.accept()
        except Exception as e:
            print(f'An error occurred during update_link: {e}')
            
    def fetch_clickable_links(self):
        try:   
            links_data = supabase.table('docs').select('links').eq('doc_id', docId).execute().data
            clickable_links = links_data[0]['links'] if links_data else {}
            links_browser = QTextBrowser()
            for original_text, link in clickable_links.items():
                links_browser.append(f'<a href="{link}">{original_text}</a>')
                
            links_browser.anchorClicked.connect(self.handle_link_click)
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Your Links")
            layout = QVBoxLayout()
            layout.addWidget(links_browser)
            dialog.setLayout(layout)
            
            dialog.exec_()
        except Exception as e:
            print(f'An error occurred during fetch_clickable_links: {e}') 
            
    def handle_link_click(self, link):
        QDesktopServices.openUrl(QUrl(link.url())) 
        
    def text_edit_changed(self):
        try:
            links_data = supabase.table('docs').select('links').eq('doc_id', docId).execute().data
            current_links = links_data[0]['links'] if links_data else {}
            
            for original_text in list(current_links.keys()):
                if original_text not in self.text_edit.toHtml():
                    # current_links.pop(original_text)
                    del current_links[original_text]
                    
            supabase.table('docs').update({'links': current_links}).eq('doc_id', docId).execute() 
        except Exception as e:
            print(f'An error occurred during text_edit_changed: {e}')
                
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
        
    def generate_doc_id(self):
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
            supabase.table('docs').insert([{'doc_id': new_doc_id, 'name': doc_name, 'users': [userId]}]).execute()
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
        self.navbar.label.setText(f"Hi {username}!")
        global docName
        docName = doc_name
        self.update_text_edit()
    
    def fetch_and_update_content(self):
        try:
            cursor_position = self.text_edit.textCursor().position()
            doc_query = supabase.table('docs').select('content', 'access').eq('doc_id', docId).execute()
            user_uuids = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
            
            if doc_query and doc_query.data:
                latest_content = doc_query.data[0]['content']
                access_level = doc_query.data[0]['access']
                
                if latest_content != self.text_edit.toHtml():
                    cursor = self.text_edit.textCursor()
                    cursor.setPosition(cursor_position)
                    self.text_edit.setText(latest_content)
                    
                if access_level:
                    if access_level == "Restricted":
                        icon = QIcon("resources/images/lock.png")
                        self.navbar.pushButton_6.setIcon(icon)
                    elif access_level == "Readable":
                        icon = QIcon("resources/images/read.png")
                        self.navbar.pushButton_6.setIcon(icon)
                    else:
                        icon = QIcon("resources/images/write.png")
                        self.navbar.pushButton_6.setIcon(icon)
                        
            if (userId in user_uuids):
                if userId == user_uuids[0]:
                    self.text_edit.setReadOnly(False)
                    self.navbar.menuBar().findChild(QMenu, "menuAccess").setEnabled(True)
                else:
                    user_access = supabase.table('docs').select('user_access').eq('doc_id', docId).execute().data[0]['user_access']
                    access_type = user_access[userId]
                    if access_type == 'Restricted':
                        if userId: user_uuids.remove(userId)
                        supabase.table('docs').update({'users': user_uuids}).eq('doc_id', docId).execute()
                        self.switch_to_home()
                    elif access_type == 'Reader':
                        self.text_edit.setReadOnly(True)
                    else:
                        self.text_edit.setReadOnly(False)
                    self.navbar.menuBar().findChild(QMenu, "menuAccess").setEnabled(False)
            else:  
                access_type = supabase.table('docs').select('access').eq('doc_id', docId).execute().data[0]['access']
                if access_type == "Restricted":
                    self.switch_to_home()
                if access_type == "Readable":
                    self.navbar.menuBar().findChild(QMenu, "menuAccess").setEnabled(False)
                    self.text_edit.setReadOnly(True)
                else:
                    self.navbar.menuBar().findChild(QMenu, "menuAccess").setEnabled(False)
                    self.text_edit.setReadOnly(False)
                    
        except Exception as e:
            print(f'An error occurred during fetch_and_update_content: {e}')
            
    def update_text_edit(self):
        try:
            user_uuids = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
            if (userId in user_uuids):
                if userId == user_uuids[0]:
                    initial_data = supabase.table('docs').select('content').eq('doc_id', docId).execute().data[0]['content']
                    print(f'Initial data: {initial_data}')
                    self.text_edit.setText(initial_data)
                    self.text_edit.setReadOnly(False)
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
                        self.text_edit.setReadOnly(True)
                        AuthenticationManager.show_popup("Access Granted", "You have read-only access to this document.")
                    elif access_type == 'Writer':
                        self.text_edit.setReadOnly(False)
                        AuthenticationManager.show_popup("Access Granted", "You have read-write access to this document.")
                    self.navbar.menuBar().findChild(QMenu, 'menuAccess').setEnabled(False)
            else:
                access_type = supabase.table('docs').select('access').eq('doc_id', docId).execute().data[0]['access']
                if access_type == 'Restricted':
                    AuthenticationManager.show_popup("Restricted Access", "You do not have access to this document.")
                    self.switch_to_home()
                if access_type == "Readable":
                    initial_data = supabase.table('docs').select('content').eq('doc_id', docId).execute().data[0]['content']
                    print(f"Initial data: {initial_data}")
                    self.text_edit.setReadOnly(True)
                    self.navbar.menuBar().findChild(QMenu, 'menuAccess').setEnabled(False)
                    AuthenticationManager.show_popup("Access Granted", "You have read-only access to this document.")
                if access_type == "Writable":
                    initial_data = supabase.table('docs').select('content').eq('doc_id', docId).execute().data[0]['content']
                    print(f"Initial data: {initial_data}")
                    self.text_edit.setReadOnly(False)
                    self.navbar.menuBar().findChild(QMenu, 'menuAccess').setEnabled(False)
                    AuthenticationManager.show_popup("Access Granted", "You have write access to this document.")
                    
            self.start_sync_timer()
            
        except Exception as e:
            print(f'An error occurred during update_text_edit: {e}')
            
            
    def start_sync_timer(self):
        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self.fetch_and_update_content)
        self.sync_timer.start(25)
        print("Sync timer started.")
        
    def convert_to_pdf(self):
        try:
            text_content = self.text_edit.toHtml()
            
            text_document = QTextDocument()
            text_document.setHtml(text_content)
            
            doc_name = supabase.table('docs').select('name').eq('doc_id', docId).execute().data[0]['name']
            documents_folder = os.path.join(os.path.expanduser('~'), "Desktop", "Docify", "Documents")
            os.makedirs(documents_folder, exist_ok=True)
            # ~/Desktop/Docify/Documents/{file_name}.pdf
            pdf_file_path = os.path.join(documents_folder, f"{doc_name}.pdf")
            
            printer = QPrinter()
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(pdf_file_path)
            
            text_document.print_(printer)
            AuthenticationManager.show_popup("PDF Created", f"PDF created at {pdf_file_path}")
        except Exception as e:
            print(f'An error occurred during convert_to_pdf: {e}')
            
    def update_access(self, access_level):
        try:
            doc_id = supabase.table('docs').select('doc_id').eq('name', docName).execute().data[0]['doc_id']
            supabase.table('docs').update({'access': access_level}).eq('doc_id', doc_id).execute()
            AuthenticationManager.show_popup("Access Updated", f"Access level updated to {access_level}.")
        except Exception as e:
            print(f'An error occurred during update_access: {e}')
            AuthenticationManager.show_popup("Error", "An error occurred during update_access.")
            
    def open_share_dialog(self, doc_name):
        share_dialog = ShareDialog(doc_name)
        userIds = supabase.table('docs').select('users').eq('doc_id', docId).execute().data[0]['users']
        if userId != userIds[0]:
            share_dialog.lineEdit.setPlaceholderText("You are not the owner")
            share_dialog.lineEdit.setEnabled(False)
            share_dialog.comboBox.setEnabled(False)
            share_dialog.pushButtonDone.setEnabled(False)
        share_dialog.exec_()
        
    def generate_general_access_link(self, doc_id, access_type):
        # "https://wwww.docify.com/document/doc_id/access_type"
        base_url = "https://www.docify.com/document/"
        access_link = f'{base_url}{doc_id}/{access_type}'
        return access_link
    
    def copy_access_link(self):
        access_type = supabase.table('docs').select('access').eq('doc_id', docId).execute().data[0]['access']
        if access_type == 'Readable':
            access_type = 'read'
        else:
            access_type = 'write'
        access_link = MainWindow.generate_general_access_link(self, docId, access_type)
        
        clipboard = QApplication.clipboard()
        clipboard.setText(access_link)
        
        AuthenticationManager.show_popup("Link Copied", "Link copied to clipboard.")
        
    def handle_access_link(self):
        try:
            url = self.home_page.lineEditAccess.text()
            path_segments = url.split('/')
            doc_id = path_segments[4] if len(path_segments) > 3 else None
            doc_name = supabase.table('docs').select('name').eq('doc_id', doc_id).execute().data[0]['name']
            
            if doc_id:
                self.open_doc(doc_name)
            else:
                AuthenticationManager.show_popup("Error", "Invalid URL.")
        except Exception as e:
            print(f'An error occurred during handle_access_link: {e}')
            AuthenticationManager.show_popup("Error", "An error occurred during handle_access_link.")
            
    def switch_to_login(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.login_page)
            
    def switch_to_signup(self, event):
        if event.button() == Qt.LeftButton:
            self.stacked_widget.setCurrentWidget(self.signup_page)
        
    def logout(self):
        self.auth_manager.logout()
        self.stacked_widget.setCurrentWidget(self.login_page)

    def make_bold(self):
        try:
            cursor_position = self.text_edit.textCursor().position()
            if self.text_edit.fontWeight() == QFont.Bold:
                self.text_edit.setFontWeight(QFont.Normal)
                self.navbar.pushButton.setStyleSheet("background-color: #FFFFFF;")
            else:
                self.text_edit.setFontWeight(QFont.Bold)
                self.navbar.pushButton.setStyleSheet("background-color: #68B7DE;")

            cursor = self.text_edit.textCursor()
            cursor.setPosition(cursor_position)
            self.text_edit.setTextCursor(cursor)
        except Exception as e:
            print(f'An error occurred during make_bold: {e}')

    def make_italic(self):
        try:
            cursor_position = self.text_edit.textCursor().position()
            if self.text_edit.fontItalic():
                self.text_edit.setFontItalic(False)
                self.navbar.pushButton_2.setStyleSheet("background-color: #FFFFFF;")
            else:
                self.text_edit.setFontItalic(True)
                self.navbar.pushButton_2.setStyleSheet("background-color: #68B7DE;")
            cursor = self.text_edit.textCursor()
            cursor.setPosition(cursor_position)
            self.text_edit.setTextCursor(cursor)
        except Exception as e:
            print(f'An error occurred during make_italic: {e}')

    def make_underline(self):
        try:
            cursor_position = self.text_edit.textCursor().position()
            if self.text_edit.fontUnderline():
                self.text_edit.setFontUnderline(False)
                self.navbar.pushButton_3.setStyleSheet("background-color: #FFFFFF;")
            else:
                self.text_edit.setFontUnderline(True)
                self.navbar.pushButton_3.setStyleSheet("background-color: #68B7DE;")
            cursor = self.text_edit.textCursor()
            cursor.setPosition(cursor_position)
            self.text_edit.setTextCursor(cursor)
        except Exception as e:
            print(f'An error occurred during make_underline: {e}')

    def change_colour(self):
        cursor_position = self.text_edit.textCursor().position()
        colour = QColorDialog.getColor()
        self.text_edit.setTextColor(colour)
        cursor = self.text_edit.textCursor()
        cursor.setPosition(cursor_position)
        self.text_edit.setTextCursor(cursor)

    def change_font(self):
        cursor_position = self.text_edit.textCursor().position()
        font, ok = QFontDialog.getFont()
        if font and ok:
            self.text_edit.setCurrentFont(font)
            if font.bold():
                self.navbar.pushButton.setStyleSheet("background-color: #68B7DE;")
            else:
                self.navbar.pushButton.setStyleSheet("background-color: #FFFFFF;")
            if font.italic():
                self.navbar.pushButton_2.setStyleSheet("background-color: #68B7DE;")
            else:
                self.navbar.pushButton_2.setStyleSheet("background-color: #FFFFFF;")
            if font.underline():
                self.navbar.pushButton_3.setStyleSheet("background-color: #68B7DE;")
            else:
                self.navbar.pushButton_3.setStyleSheet("background-color: #FFFFFF;")
        
        cursor = self.text_edit.textCursor()
        cursor.setPosition(cursor_position)
        self.text_edit.setTextCursor(cursor)
            
    
    
if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())