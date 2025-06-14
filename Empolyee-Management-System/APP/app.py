import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import uuid
import csv
import time
import hashlib
import re
import logging

# --- Configuration ---
DATABASE_USERS = "users.db"
DATABASE_EMPLOYEES = "employees.db"
DEFAULT_ADMIN_USERNAME = "Admin"
DEFAULT_ADMIN_PASSWORD = "8958583976"
 # In a real application, this would be a secure, hashed password

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---
def hash_password(password):
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def validate_email(email):
    """Validates an email address format."""
    return re.fullmatch(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email)

# --- Database Manager Class ---
class DatabaseManager:
    """Manages SQLite database connections and operations."""
    def __init__(self, db_name):
        self.db_name = db_name

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_name)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.cursor = self.conn.cursor()
        return self.cursor

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logging.error(f"Database error in {self.db_name}: {exc_val}", exc_info=True)
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

    def execute_query(self, query, params=()):
        try:
            with self as cursor:
                cursor.execute(query, params)
            return True
        except sqlite3.IntegrityError as e:
            logging.warning(f"Integrity Error executing query '{query}' with params {params}: {e}")
            messagebox.showerror("Database Error", f"A data integrity error occurred: {e}. This might mean a duplicate entry for a unique field like Email.")
            return False
        except sqlite3.Error as e:
            logging.error(f"Database error executing query '{query}' with params {params}: {e}", exc_info=True)
            messagebox.showerror("Database Error", f"An error occurred during database operation: {e}")
            return False
        except Exception as e:
            logging.critical(f"Unexpected error in execute_query: {e}", exc_info=True)
            messagebox.showerror("Critical Error", f"An unexpected error occurred: {e}")
            return False

    def fetch_all(self, query, params=()):
        try:
            with self as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Database error fetching all with query '{query}' and params {params}: {e}", exc_info=True)
            messagebox.showerror("Database Error", f"An error occurred retrieving data: {e}")
            return []
        except Exception as e:
            logging.critical(f"Unexpected error in fetch_all: {e}", exc_info=True)
            messagebox.showerror("Critical Error", f"An unexpected error occurred: {e}")
            return []

    def fetch_one(self, query, params=()):
        try:
            with self as cursor:
                cursor.execute(query, params)
                return cursor.fetchone()
        except sqlite3.Error as e:
            logging.error(f"Database error fetching one with query '{query}' and params {params}: {e}", exc_info=True)
            messagebox.showerror("Database Error", f"An error occurred retrieving data: {e}")
            return None
        except Exception as e:
            logging.critical(f"Unexpected error in fetch_one: {e}", exc_info=True)
            messagebox.showerror("Critical Error", f"An unexpected error occurred: {e}")
            return None

# --- Auth Manager Class ---
class AuthManager:
    """Handles user authentication and registration."""
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self._create_users_table()
        self._insert_default_admin()

    def _create_users_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        '''
        self.db_manager.execute_query(query)
        logging.info("Users table checked/created.")

    def _insert_default_admin(self):
        query = "SELECT * FROM users WHERE username=?"
        if not self.db_manager.fetch_one(query, (DEFAULT_ADMIN_USERNAME,)):
            hashed_password = hash_password(DEFAULT_ADMIN_PASSWORD)
            if self.db_manager.execute_query(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (DEFAULT_ADMIN_USERNAME, hashed_password, "admin")
            ):
                logging.info(f"Default admin user '{DEFAULT_ADMIN_USERNAME}' inserted.")
            else:
                logging.error(f"Failed to insert default admin user '{DEFAULT_ADMIN_USERNAME}'.")

    def authenticate_user(self, username, password):
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password.")
            return None

        hashed_password = hash_password(password)
        query = "SELECT password, role FROM users WHERE username=?"
        result = self.db_manager.fetch_one(query, (username,))

        if result and result[0] == hashed_password:
            logging.info(f"User '{username}' authenticated successfully with role '{result[1]}'.")
            return result[1]
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            logging.warning(f"Failed login attempt for username: '{username}'.")
            return None

    def register_user(self, username, password, confirm_password, role):
        if not all([username, password, confirm_password]):
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return False
        if password != confirm_password:
            messagebox.showerror("Password Error", "Passwords do not match.")
            return False
        if len(password) < 6:
            messagebox.showwarning("Password Policy", "Password must be at least 6 characters long.")
            return False

        query = "SELECT * FROM users WHERE username=?"
        if self.db_manager.fetch_one(query, (username,)):
            messagebox.showerror("Registration Error", "Username already exists.")
            logging.warning(f"Registration failed: Username '{username}' already exists.")
            return False

        hashed_password = hash_password(password)
        if self.db_manager.execute_query(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        ):
            messagebox.showinfo("Success", f"User '{username}' registered successfully! You can now login.")
            logging.info(f"New user '{username}' registered with role '{role}'.")
            return True
        return False

    def reset_password(self, username, new_password):
        if not all([username, new_password]):
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return False
        if len(new_password) < 6:
            messagebox.showwarning("Password Policy", "New password must be at least 6 characters long.")
            return False

        query = "SELECT * FROM users WHERE username=?"
        if self.db_manager.fetch_one(query, (username,)):
            hashed_new_password = hash_password(new_password)
            if self.db_manager.execute_query(
                "UPDATE users SET password=? WHERE username=?",
                (hashed_new_password, username)
            ):
                messagebox.showinfo("Success", "Password updated successfully.")
                logging.info(f"Password reset for user '{username}'.")
                return True
            return False
        else:
            messagebox.showerror("Error", "Username not found.")
            logging.warning(f"Password reset failed: Username '{username}' not found.")
            return False

# --- Main Application Class (Login/Register) ---
class App(ctk.CTk):
    """Main application class handling user authentication and navigation."""
    def __init__(self):
        super().__init__()
        self.title("Employee Management System")
        self.geometry()
        self.resizable(True, True)

        ctk.set_appearance_mode("System")  # Use system default light/dark mode
        ctk.set_default_color_theme("blue") # Default CTk theme

        self.user_db_manager = DatabaseManager(DATABASE_USERS)
        self.auth_manager = AuthManager(self.user_db_manager)

        self.current_user_role = None
        
        self._show_login_register_ui()

    def _clear_widgets(self):
        """Destroys all widgets in the root window."""
        for widget in self.winfo_children():
            widget.destroy()

    def _show_login_register_ui(self):
        """Sets up the login and registration interface."""
        self._clear_widgets()

        # CTkTabview for Login/Register
        self.tabview = ctk.CTkTabview(self, width=400, height=450, segmented_button_fg_color=("gray80", "gray20"))
        self.tabview.pack(expand=True, padx=50, pady=60)

        self.login_tab = self.tabview.add("Login")
        self.register_tab = self.tabview.add("Register")

        self._setup_login_frame_content(self.login_tab)
        self._setup_register_frame_content(self.register_tab)

    def _setup_login_frame_content(self, frame):
        """Configures the login UI elements."""
        self.login_username_var = ctk.StringVar()
        self.login_password_var = ctk.StringVar()

        ctk.CTkLabel(frame, text="Welcome Back!", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=25)

        ctk.CTkLabel(frame, text="Username").pack(anchor="w", padx=40, pady=(10,0))
        ctk.CTkEntry(frame, textvariable=self.login_username_var, placeholder_text="Enter username", font=("Helvetica", 13), width=300).pack(padx=40, pady=5)

        ctk.CTkLabel(frame, text="Password").pack(anchor="w", padx=40, pady=(10,0))
        ctk.CTkEntry(frame, textvariable=self.login_password_var, placeholder_text="Enter password", font=("Helvetica", 13), show="*", width=300).pack(padx=40, pady=5)

        ctk.CTkButton(frame, text="Login", font=ctk.CTkFont(size=14, weight="bold"),
                      command=self._authenticate_user_ui, width=300).pack(pady=25)

        ctk.CTkButton(frame, text="Forgot Password?", fg_color="transparent", text_color=("blue", "lightblue"),
                      font=("Helvetica", 11, "underline"), hover_color=("gray90", "gray30"),
                      command=self._password_reset_popup).pack()

    def _setup_register_frame_content(self, frame):
        """Configures the registration UI elements."""
        self.reg_username_var = ctk.StringVar()
        self.reg_password_var = ctk.StringVar()
        self.reg_confirm_password_var = ctk.StringVar()
        self.reg_role_var = ctk.StringVar(value="user")

        ctk.CTkLabel(frame, text="Create New Account", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=25)

        ctk.CTkLabel(frame, text="Username").pack(anchor="w", padx=40, pady=(10,0))
        ctk.CTkEntry(frame, textvariable=self.reg_username_var, placeholder_text="Choose username", font=("Helvetica", 13), width=300).pack(padx=40, pady=5)

        ctk.CTkLabel(frame, text="Password").pack(anchor="w", padx=40, pady=(10,0))
        ctk.CTkEntry(frame, textvariable=self.reg_password_var, placeholder_text="Create password", font=("Helvetica", 13), show="*", width=300).pack(padx=40, pady=5)

        ctk.CTkLabel(frame, text="Confirm Password").pack(anchor="w", padx=40, pady=(10,0))
        ctk.CTkEntry(frame, textvariable=self.reg_confirm_password_var, placeholder_text="Confirm password", font=("Helvetica", 13), show="*", width=300).pack(padx=40, pady=5)

        role_frame = ctk.CTkFrame(frame, fg_color="transparent")
        role_frame.pack(pady=15)
        ctk.CTkLabel(role_frame, text="Select Role:").pack(side="left", padx=10)
        ctk.CTkRadioButton(role_frame, text="User", variable=self.reg_role_var, value="user").pack(side="left", padx=15)
        ctk.CTkRadioButton(role_frame, text="Admin", variable=self.reg_role_var, value="admin").pack(side="left", padx=15)

        ctk.CTkButton(frame, text="Register", font=ctk.CTkFont(size=14, weight="bold"),
                      command=self._register_user_ui, width=300).pack(pady=10)

    def _authenticate_user_ui(self):
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get().strip()
        role = self.auth_manager.authenticate_user(username, password)
        if role:
            self.current_user_role = role
            self._animate_transition(lambda: self._show_dashboard(ctk.get_appearance_mode()))

    def _register_user_ui(self):
        username = self.reg_username_var.get().strip()
        password = self.reg_password_var.get().strip()
        confirm_password = self.reg_confirm_password_var.get().strip()
        role = self.reg_role_var.get()

        if self.auth_manager.register_user(username, password, confirm_password, role):
            self.reg_username_var.set("")
            self.reg_password_var.set("")
            self.reg_confirm_password_var.set("")
            self.reg_role_var.set("user")
            self.tabview.set("Login") # Switch back to login tab

    def _password_reset_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Reset Password")
        popup.geometry("350x200")
        popup.transient(self)
        popup.grab_set()

        ctk.CTkLabel(popup, text="Enter Username:").pack(pady=10)
        username_entry = ctk.CTkEntry(popup, width=250)
        username_entry.pack()

        ctk.CTkLabel(popup, text="Enter New Password:").pack(pady=10)
        password_entry = ctk.CTkEntry(popup, show="*", width=250)
        password_entry.pack()

        def perform_reset():
            username = username_entry.get().strip()
            new_pass = password_entry.get().strip()
            if self.auth_manager.reset_password(username, new_pass):
                popup.destroy()

        ctk.CTkButton(popup, text="Reset Password", command=perform_reset).pack(pady=15)

    def _animate_transition(self, next_page_func):
        # Fade out
        for i in range(20, -1, -1):
            self.attributes("-alpha", i / 20)
            self.update_idletasks()
            time.sleep(0.01)
        
        next_page_func()

        # Fade in
        for i in range(0, 21):
            self.attributes("-alpha", i / 20)
            self.update_idletasks()
            time.sleep(0.01)
        self.attributes("-alpha", 1.0)

    def _show_dashboard(self, initial_theme_mode):
        self._clear_widgets()
        # Initialize Dashboard
        self.dashboard_instance = EmployeeManagementDashboard(
            self, # Pass self (the CTk root) as parent
            self.current_user_role,
            self._logout_from_dashboard,
            initial_theme_mode # Pass current theme mode
        )

    def _logout_from_dashboard(self):
        logging.info(f"User '{self.current_user_role}' logged out.")
        self.current_user_role = None
        ctk.set_appearance_mode("System") # Reset theme on logout
        self._animate_transition(self._show_login_register_ui)

# --- Employee Management Dashboard Class ---
class EmployeeManagementDashboard(ctk.CTkFrame): # Inherit from CTkFrame for dashboard content
    """Manages the employee data and dashboard UI."""
    def __init__(self, master, user_role, logout_callback, initial_theme_mode):
        super().__init__(master, corner_radius=0, fg_color="transparent") # Take up entire master
        self.pack(fill="both", expand=True)

        self.master = master # Store master (App instance)
        self.user_role = user_role
        self.logout_callback = logout_callback
        
        ctk.set_appearance_mode(initial_theme_mode) # Set dashboard's initial theme

        self.db_manager = DatabaseManager(DATABASE_EMPLOYEES)
        self._create_employee_table()
        self._setup_ui()
        self._load_employees()

    def _create_employee_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS employees (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                age INTEGER,
                department TEXT,
                salary REAL,
                email TEXT UNIQUE,
                position TEXT
            )
        '''
        self.db_manager.execute_query(query)
        logging.info("Employees table checked/created.")

    def _setup_ui(self):
        # Top Bar
        top_bar = ctk.CTkFrame(self, fg_color="transparent")
        top_bar.pack(fill="x", pady=(10, 0), padx=20)

        ctk.CTkLabel(top_bar, text="Employee Management Dashboard", font=ctk.CTkFont(size=28, weight="bold")).pack(side="left", padx=10)

        # Theme Switch
        self.theme_switch_var = ctk.StringVar(value=ctk.get_appearance_mode())
        self.theme_switch = ctk.CTkSwitch(top_bar, text="Dark Mode", command=self._toggle_theme,
                                          variable=self.theme_switch_var, onvalue="Dark", offvalue="Light")
        self.theme_switch.pack(side="left", padx=20)
        # Set initial switch state based on current theme
        if ctk.get_appearance_mode() == "Dark":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()

        ctk.CTkButton(top_bar, text="Logout", command=self.logout_callback, fg_color="red", hover_color="darkred").pack(side="right", padx=10)

        # Main Content Frame - splits into left (form) and right (table)
        main_content_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # --- Left Panel: Input Form ---
        form_panel = ctk.CTkFrame(main_content_frame, width=350)
        form_panel.pack(side="left", fill="y", padx=(0, 10), pady=10)
        form_panel.pack_propagate(False) # Prevent frame from resizing to content

        ctk.CTkLabel(form_panel, text="Employee Details", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=15)

        # Form variables
        self.id_var = ctk.StringVar()
        self.name_var = ctk.StringVar()
        self.age_var = ctk.IntVar(value=0) # Default age to 0 or something reasonable
        self.dept_var = ctk.StringVar()
        self.salary_var = ctk.StringVar()
        self.email_var = ctk.StringVar()
        self.position_var = ctk.StringVar()

        # Input fields
        fields_data = [
            ("Name", self.name_var, "Enter full name"),
            ("Age", self.age_var, "Enter age (18-100)"),
            ("Department", self.dept_var, ["IT", "HR", "Sales", "Finance", "Marketing", "Operations"]), # Using list for Combobox
            ("Salary", self.salary_var, "Enter salary"),
            ("Email", self.email_var, "Enter email address"),
            ("Position", self.position_var, "Enter job position")
        ]

        for label_text, var, placeholder_or_values in fields_data:
            ctk.CTkLabel(form_panel, text=label_text + ":").pack(anchor="w", padx=25, pady=(5, 0))
            if isinstance(placeholder_or_values, list):
                ctk.CTkComboBox(form_panel, variable=var, values=placeholder_or_values, width=300).pack(padx=25, pady=(0, 10))
            else:
                entry_widget = ctk.CTkEntry(form_panel, textvariable=var, placeholder_text=placeholder_or_values, width=300)
                entry_widget.pack(padx=25, pady=(0, 10))
                if label_text == "Age":
                    reg = self.register(self._validate_age_input)
                    entry_widget.configure(validate="key", validatecommand=(reg, '%P'))
                elif label_text == "Salary":
                    reg = self.register(self._validate_salary_input)
                    entry_widget.configure(validate="key", validatecommand=(reg, '%P'))

        # Action Buttons
        btn_frame = ctk.CTkFrame(form_panel, fg_color="transparent")
        btn_frame.pack(pady=10)

        if self.user_role == "admin":
            ctk.CTkButton(btn_frame, text="Add Employee", command=self._add_employee).grid(row=0, column=0, padx=5, pady=5)
            ctk.CTkButton(btn_frame, text="Update Employee", command=self._update_employee, fg_color="orange").grid(row=0, column=1, padx=5, pady=5)
            ctk.CTkButton(btn_frame, text="Delete Employee", command=self._delete_employee, fg_color="red").grid(row=1, column=0, padx=5, pady=5)
            ctk.CTkButton(btn_frame, text="Clear Form", command=self._clear_form, fg_color="gray").grid(row=1, column=1, padx=5, pady=5)
        
        ctk.CTkButton(btn_frame, text="Export CSV", command=self._export_csv, fg_color="green").grid(row=2, column=0, padx=5, pady=5)
        if self.user_role == "admin":
            ctk.CTkButton(btn_frame, text="Import CSV", command=self._import_csv, fg_color="purple").grid(row=2, column=1, padx=5, pady=5)


        # --- Right Panel: Treeview / Data Display ---
        display_panel = ctk.CTkFrame(main_content_frame)
        display_panel.pack(side="right", fill="both", expand=True, padx=(10, 0), pady=10)

        # Search Bar
        search_frame = ctk.CTkFrame(display_panel, fg_color="transparent")
        search_frame.pack(fill="x", pady=(0, 10))
        
        self.search_var = ctk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Search by Name or Email", width=300).pack(side="left", padx=10, expand=True, fill="x")
        ctk.CTkButton(search_frame, text="Search", command=self._search_employee).pack(side="left", padx=5)
        ctk.CTkButton(search_frame, text="Show All", command=self._load_employees, fg_color="gray").pack(side="left", padx=5)


        # Treeview styling with ttk.Style - needs to be updated dynamically
        self.style = ttk.Style()
        self.style.theme_use('clam') # Clam theme often blends well with CTk

        self._configure_treeview_style() # Initial configuration

        columns = ("ID", "Name", "Age", "Department", "Salary", "Email", "Position")
        self.tree = ttk.Treeview(display_panel, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.tree.heading(col, text=col, anchor="w", command=lambda c=col: self._sort_treeview(self.tree, c, False))
            if col == "ID":
                self.tree.column(col, width=0, stretch=False) # Hide ID column
            elif col == "Name":
                self.tree.column(col, width=150, anchor="w")
            elif col == "Email":
                self.tree.column(col, width=200, anchor="w")
            else:
                self.tree.column(col, width=100, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        if self.user_role == "admin":
            self.tree.bind("<<TreeviewSelect>>", self._select_employee)
        else:
            # Prevent selection for non-admin users, or allow selection but disable form
            self.tree.bind("<<TreeviewSelect>>", lambda e: self.master.after(1, self.tree.selection_remove, self.tree.selection()))


    def _configure_treeview_style(self):
        # Dynamically set Treeview colors based on current CTk theme
        if ctk.get_appearance_mode() == "Dark":
            tree_bg = "#2B2B2B"  # Dark mode background for treeview
            tree_fg = "white"
            tree_heading_bg = "#404040" # Darker gray for headers
            tree_selected_bg = "#3A8EBB" # A blue for selected row in dark mode
        else: # Light Mode
            tree_bg = "#EAEAEA"  # Light gray background for treeview
            tree_fg = "black"
            tree_heading_bg = "#C0C0C0" # Light gray for headers
            tree_selected_bg = "#87CEEB" # Sky blue for selected row in light mode

        self.style.configure("Treeview",
                             background=tree_bg,
                             foreground=tree_fg,
                             fieldbackground=tree_bg,
                             bordercolor=tree_heading_bg,
                             lightcolor=tree_heading_bg,
                             darkcolor=tree_heading_bg)
        self.style.map('Treeview',
                       background=[('selected', tree_selected_bg)])
        self.style.configure("Treeview.Heading",
                             font=("Arial", 12, "bold"),
                             background=tree_heading_bg,
                             foreground=tree_fg, # Use foreground based on theme
                             relief="flat") # Flat look for headings
        self.style.map("Treeview.Heading",
                       background=[('active', tree_heading_bg)]) # No change on active hover


    def _toggle_theme(self):
        current_mode = ctk.get_appearance_mode()
        new_mode = "Dark" if current_mode == "Light" else "Light"
        ctk.set_appearance_mode(new_mode)
        self._configure_treeview_style() # Re-apply Treeview styles after theme change
        # Update switch text
        self.theme_switch_var.set(new_mode)

    def _validate_age_input(self, new_value):
        if new_value == "": return True
        if new_value.isdigit() and 0 <= int(new_value) <= 120 and len(new_value) <= 3:
            return True
        return False

    def _validate_salary_input(self, new_value):
        if new_value == "": return True
        try:
            float(new_value)
            return True
        except ValueError:
            return False

    def _validate_employee_data(self, name, age, department, salary, email, position):
        if not all([name, department, email, position]):
            messagebox.showwarning("Input Error", "Name, Department, Email, and Position are required.")
            return False
        
        if not all(char.isalpha() or char.isspace() for char in name):
             messagebox.showwarning("Input Error", "Name must contain only alphabetic characters and spaces.")
             return False

        try:
            age_int = int(age)
            if not (18 <= age_int <= 100):
                messagebox.showwarning("Input Error", "Age must be between 18 and 100.")
                return False
        except ValueError:
            messagebox.showwarning("Input Error", "Age must be a valid number.")
            return False

        try:
            salary_float = float(salary)
            if not (salary_float >= 0):
                messagebox.showwarning("Input Error", "Salary cannot be negative.")
                return False
        except ValueError:
            messagebox.showwarning("Input Error", "Salary must be a valid number.")
            return False

        if not validate_email(email):
            messagebox.showwarning("Input Error", "Please enter a valid email address.")
            return False
        
        return True

    def _add_employee(self):
        name = self.name_var.get().strip()
        age = self.age_var.get()
        dept = self.dept_var.get().strip()
        salary = self.salary_var.get().strip()
        email = self.email_var.get().strip()
        position = self.position_var.get().strip()

        if not self._validate_employee_data(name, age, dept, salary, email, position):
            return

        emp_id = str(uuid.uuid4())
        try:
            age_val = int(age)
            salary_val = float(salary)
        except ValueError:
            messagebox.showerror("Data Type Error", "Failed to convert Age or Salary to number.")
            return

        if self.db_manager.execute_query(
            "INSERT INTO employees (id, name, age, department, salary, email, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (emp_id, name, age_val, dept, salary_val, email, position)
        ):
            messagebox.showinfo("Success", f"Employee '{name}' added successfully!")
            logging.info(f"Added employee: {name} ({emp_id})")
            self._load_employees()
            self._clear_form()

    def _update_employee(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an employee to update.")
            return

        emp_id_from_tree = self.tree.item(selected_item[0], "values")[0]
        if not emp_id_from_tree:
            messagebox.showerror("Error", "No employee ID found for update.")
            return

        name = self.name_var.get().strip()
        age = self.age_var.get()
        dept = self.dept_var.get().strip()
        salary = self.salary_var.get().strip()
        email = self.email_var.get().strip()
        position = self.position_var.get().strip()

        if not self._validate_employee_data(name, age, dept, salary, email, position):
            return

        try:
            age_val = int(age)
            salary_val = float(salary)
        except ValueError:
            messagebox.showerror("Data Type Error", "Failed to convert Age or Salary to number.")
            return

        if self.db_manager.execute_query(
            "UPDATE employees SET name=?, age=?, department=?, salary=?, email=?, position=? WHERE id=?",
            (name, age_val, dept, salary_val, email, position, emp_id_from_tree)
        ):
            messagebox.showinfo("Success", f"Employee '{name}' updated successfully!")
            logging.info(f"Updated employee: {name} ({emp_id_from_tree})")
            self._load_employees()
            self._clear_form()

    def _delete_employee(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an employee to delete.")
            return

        emp_id = self.tree.item(selected_item[0], "values")[0]
        name = self.tree.item(selected_item[0], "values")[1]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete employee '{name}'? This action cannot be undone."):
            if self.db_manager.execute_query("DELETE FROM employees WHERE id=?", (emp_id,)):
                messagebox.showinfo("Success", f"Employee '{name}' deleted successfully!")
                logging.info(f"Deleted employee: {name} ({emp_id})")
                self._load_employees()
                self._clear_form()

    def _select_employee(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], "values")
            self.id_var.set(values[0])
            self.name_var.set(values[1])
            self.age_var.set(values[2])
            self.dept_var.set(values[3])
            self.salary_var.set(values[4])
            self.email_var.set(values[5])
            self.position_var.set(values[6])
            logging.debug(f"Selected employee ID: {values[0]}")
        else:
            self._clear_form()

    def _load_employees(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        rows = self.db_manager.fetch_all("SELECT * FROM employees ORDER BY name ASC")
        for row in rows:
            self.tree.insert("", "end", values=row)
        logging.info("Employees loaded into Treeview.")

    def _sort_treeview(self, tv, col, reverse):
        # Grab the list of values to sort
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        
        # Determine sorting type (numeric for age/salary, alphabetic for others)
        try:
            if col in ("Age", "Salary"):
                l.sort(key=lambda t: float(t[0]), reverse=reverse)
            else:
                l.sort(key=lambda t: t[0].lower(), reverse=reverse)
        except ValueError:
            # Fallback to string sort if conversion fails
            l.sort(key=lambda t: t[0].lower(), reverse=reverse)

        # Rearrange items in sorted order
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        # Reverse sort next time
        tv.heading(col, command=lambda: self._sort_treeview(tv, col, not reverse))


    def _search_employee(self):
        query_text = self.search_var.get().strip().lower()
        
        for i in self.tree.get_children():
            self.tree.delete(i)

        if not query_text:
            self._load_employees()
            return
        
        search_pattern = f"%{query_text}%"
        rows = self.db_manager.fetch_all(
            "SELECT * FROM employees WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? ORDER BY name ASC",
            (search_pattern, search_pattern)
        )
        
        for row in rows:
            self.tree.insert("", "end", values=row)
        logging.info(f"Performed search for '{query_text}'. Found {len(rows)} results.")

    def _clear_form(self):
        self.id_var.set("")
        self.name_var.set("")
        self.age_var.set(0)
        self.dept_var.set("")
        self.salary_var.set("")
        self.email_var.set("")
        self.position_var.set("")
        if self.tree.selection():
            self.tree.selection_remove(self.tree.selection())
        logging.info("Form cleared.")

    def _export_csv(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files","*.csv")],
                                                initialfile="employees.csv")
        if not filepath:
            logging.info("CSV export cancelled by user.")
            return

        headers = ["Name", "Age", "Department", "Salary", "Email", "Position"]
        rows_to_export = self.db_manager.fetch_all("SELECT name, age, department, salary, email, position FROM employees")

        if rows_to_export is None:
            messagebox.showerror("Export Error", "Could not retrieve data for export.")
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows_to_export)
            messagebox.showinfo("Export Success", f"Data exported successfully to:\n{filepath}")
            logging.info(f"Data exported to {filepath}.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {e}")
            logging.error(f"Error during CSV export to {filepath}: {e}", exc_info=True)

    def _import_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV Files","*.csv")])
        if not filepath:
            logging.info("CSV import cancelled by user.")
            return

        try:
            with open(filepath, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                required_headers = ["Name", "Age", "Department", "Salary", "Email", "Position"]
                if not all(header in reader.fieldnames for header in required_headers):
                    messagebox.showerror("Import Error", "CSV file is missing one or more required headers: Name, Age, Department, Salary, Email, Position.")
                    logging.error(f"CSV import failed: missing headers in {filepath}. Found: {reader.fieldnames}")
                    return

                imported_count = 0
                skipped_count = 0
                for row_num, row_data in enumerate(reader, start=2):
                    name = row_data.get('Name', '').strip()
                    age_str = row_data.get('Age', '').strip()
                    dept = row_data.get('Department', '').strip()
                    salary_str = row_data.get('Salary', '').strip()
                    email = row_data.get('Email', '').strip()
                    position = row_data.get('Position', '').strip()

                    if not self._validate_employee_data(name, age_str, dept, salary_str, email, position):
                        logging.warning(f"Skipping row {row_num} due to invalid data: {row_data}")
                        skipped_count += 1
                        continue

                    try:
                        age = int(age_str)
                        salary = float(salary_str)
                    except ValueError:
                        logging.warning(f"Skipping row {row_num} due to invalid age/salary format: {row_data}")
                        skipped_count += 1
                        continue

                    emp_id = str(uuid.uuid4())
                    
                    if self.db_manager.execute_query(
                        "INSERT INTO employees (id, name, age, department, salary, email, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (emp_id, name, age, salary, email, position)
                    ):
                        imported_count += 1
                    else:
                        skipped_count += 1
                
            self._load_employees()
            messagebox.showinfo("Import Success", f"Data import complete.\n"
                                                  f"Imported: {imported_count} records.\n"
                                                  f"Skipped: {skipped_count} records (due to errors, duplicates, or missing data).")
            logging.info(f"Data imported from {filepath}. Imported: {imported_count}, Skipped: {skipped_count}.")

        except FileNotFoundError:
            messagebox.showerror("Import Error", "Selected file not found.")
            logging.error(f"File not found during CSV import: {filepath}", exc_info=True)
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import data: {e}")
            logging.error(f"General error during CSV import from {filepath}: {e}", exc_info=True)


if __name__ == "__main__":
    app = App()
    app.mainloop()