import streamlit as st
import psycopg2
import hashlib
import os
from datetime import datetime
import pandas as pd
from urllib.parse import urlparse

# Database connection functions
def parse_db_url(db_url):
    """
    Parse database connection parameters from a URL string
    Format: postgresql://username:password@host:port/database
    """
    parsed_url = urlparse(db_url)
    
    # Extract connection details
    db_host = parsed_url.hostname
    db_port = parsed_url.port or 5432  # Default port if not specified
    db_name = parsed_url.path.lstrip('/')
    db_user = parsed_url.username
    db_password = parsed_url.password
    
    # Extract query parameters for SSL mode and other options
    query_params = {}
    if parsed_url.query:
        for param in parsed_url.query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                query_params[key] = value
    
    conn_params = {
        "host": db_host,
        "port": db_port,
        "database": db_name,
        "user": db_user,
        "password": db_password
    }
    
    # Add any additional parameters from the query string
    for key, value in query_params.items():
        conn_params[key] = value
    
    return conn_params

def get_db_connection():
    try:
        # First try to get database URL from secrets.toml
        db_url = st.secrets.get("db_url", None)
        
        if db_url:
            # Parse the URL into connection parameters
            conn_params = parse_db_url(db_url)
            conn = psycopg2.connect(**conn_params)
        else:
            # Fall back to individual environment variables
            conn = psycopg2.connect(
                host=os.getenv("NEON_HOST"),
                database=os.getenv("NEON_DB"),
                user=os.getenv("NEON_USER"),
                password=os.getenv("NEON_PASSWORD"),
                port=os.getenv("NEON_PORT", "5432")
            )
        return conn
    except Exception as e:
        st.error(f"Database connection error: {e}")
        raise e

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Authentication functions
def register_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING user_id", 
                   (email, password_hash))
        user_id = cur.fetchone()[0]
        conn.commit()
        return user_id
    except psycopg2.Error as e:
        conn.rollback()
        st.error(f"Registration failed: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def login_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cur.execute("SELECT user_id, is_admin, email FROM users WHERE email = %s AND password_hash = %s", 
                   (email, password_hash))
        result = cur.fetchone()
        
        if result:
            return {"user_id": result[0], "is_admin": result[1], "email": result[2]}
        return None
    finally:
        cur.close()
        conn.close()

# Ticket management functions
def create_ticket(user_id, title, description, priority):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "INSERT INTO tickets (user_id, title, description, priority) VALUES (%s, %s, %s, %s) RETURNING ticket_id",
            (user_id, title, description, priority)
        )
        ticket_id = cur.fetchone()[0]
        conn.commit()
        return ticket_id
    except psycopg2.Error as e:
        conn.rollback()
        st.error(f"Failed to create ticket: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def get_user_tickets(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "SELECT ticket_id, title, description, priority, status, created_at FROM tickets WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        tickets = cur.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for ticket in tickets:
            result.append({
                "ticket_id": ticket[0],
                "title": ticket[1],
                "description": ticket[2],
                "priority": ticket[3],
                "status": ticket[4],
                "created_at": ticket[5]
            })
        
        return result
    finally:
        cur.close()
        conn.close()

def get_all_tickets():
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            """
            SELECT t.ticket_id, t.title, t.description, t.priority, t.status, t.created_at, u.email
            FROM tickets t
            JOIN users u ON t.user_id = u.user_id
            ORDER BY 
                CASE WHEN t.status = 'Open' THEN 1
                     WHEN t.status = 'In Progress' THEN 2
                     WHEN t.status = 'Closed' THEN 3
                END,
                CASE WHEN t.priority = 'High' THEN 1
                     WHEN t.priority = 'Medium' THEN 2
                     WHEN t.priority = 'Low' THEN 3
                END,
                t.created_at DESC
            """
        )
        tickets = cur.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for ticket in tickets:
            result.append({
                "ticket_id": ticket[0],
                "title": ticket[1],
                "description": ticket[2],
                "priority": ticket[3],
                "status": ticket[4],
                "created_at": ticket[5],
                "user_email": ticket[6]
            })
        
        return result
    finally:
        cur.close()
        conn.close()

def get_ticket_details(ticket_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get ticket details
        cur.execute(
            """
            SELECT t.ticket_id, t.title, t.description, t.priority, t.status, t.created_at, u.email, t.user_id
            FROM tickets t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.ticket_id = %s
            """,
            (ticket_id,)
        )
        ticket = cur.fetchone()
        
        if not ticket:
            return None
        
        ticket_details = {
            "ticket_id": ticket[0],
            "title": ticket[1],
            "description": ticket[2],
            "priority": ticket[3],
            "status": ticket[4],
            "created_at": ticket[5],
            "user_email": ticket[6],
            "user_id": ticket[7]
        }
        
        return ticket_details
    finally:
        cur.close()
        conn.close()

def update_ticket_status(ticket_id, status):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "UPDATE tickets SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE ticket_id = %s",
            (status, ticket_id)
        )
        conn.commit()
        return True
    except psycopg2.Error as e:
        conn.rollback()
        st.error(f"Failed to update ticket status: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# New function to delete a ticket
def delete_ticket(ticket_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # First delete all messages associated with this ticket
        cur.execute("DELETE FROM messages WHERE ticket_id = %s", (ticket_id,))
        
        # Then delete the ticket itself
        cur.execute("DELETE FROM tickets WHERE ticket_id = %s", (ticket_id,))
        
        conn.commit()
        return True
    except psycopg2.Error as e:
        conn.rollback()
        st.error(f"Failed to delete ticket: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# Message functions
def add_message(ticket_id, user_id, content):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "INSERT INTO messages (ticket_id, user_id, content) VALUES (%s, %s, %s) RETURNING message_id",
            (ticket_id, user_id, content)
        )
        message_id = cur.fetchone()[0]
        
        # Update the ticket's updated_at timestamp
        cur.execute(
            "UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE ticket_id = %s",
            (ticket_id,)
        )
        
        conn.commit()
        return message_id
    except psycopg2.Error as e:
        conn.rollback()
        st.error(f"Failed to add message: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def get_ticket_messages(ticket_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            """
            SELECT m.message_id, m.content, m.created_at, u.email, u.is_admin 
            FROM messages m
            JOIN users u ON m.user_id = u.user_id
            WHERE m.ticket_id = %s
            ORDER BY m.created_at ASC
            """,
            (ticket_id,)
        )
        messages = cur.fetchall()
        
        # Convert to list of dictionaries
        result = []
        for message in messages:
            result.append({
                "message_id": message[0],
                "content": message[1],
                "created_at": message[2],
                "user_email": message[3],
                "is_admin": message[4]
            })
        
        return result
    finally:
        cur.close()
        conn.close()

# Initialize session state
if 'user' not in st.session_state:
    st.session_state.user = None
if 'page' not in st.session_state:
    st.session_state.page = 'login'
if 'selected_ticket' not in st.session_state:
    st.session_state.selected_ticket = None
if 'confirm_delete' not in st.session_state:
    st.session_state.confirm_delete = None

# Navigation functions
def navigate_to(page):
    st.session_state.page = page
    
def logout():
    st.session_state.user = None
    st.session_state.page = 'login'
    st.session_state.selected_ticket = None

def select_ticket(ticket_id):
    st.session_state.selected_ticket = ticket_id
    st.session_state.page = 'ticket_detail'

# UI Functions
def show_login_page():
    st.title("Customer Support System")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            if email and password:
                user = login_user(email, password)
                if user:
                    st.session_state.user = user
                    st.session_state.page = 'dashboard'
                    st.rerun()
                else:
                    st.error("Invalid email or password")
            else:
                st.warning("Please enter both email and password")
    
    with tab2:
        st.subheader("Register")
        email = st.text_input("Email", key="register_email")
        password = st.text_input("Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        
        if st.button("Register"):
            if email and password and confirm_password:
                if password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    user_id = register_user(email, password)
                    if user_id:
                        st.success("Registration successful. Please login.")
                        st.session_state.page = 'login'
                        st.rerun()
            else:
                st.warning("Please fill all fields")

def show_user_dashboard():
    st.title("Customer Support Dashboard")
    st.write(f"Logged in as: {st.session_state.user.get('email', 'User')}")
    
    if st.button("Logout", key="logout_button"):
        logout()
        st.rerun()
        
    st.subheader("Your Support Tickets")
    
    # New ticket creation
    with st.expander("Create New Ticket"):
        ticket_title = st.text_input("Title")
        ticket_description = st.text_area("Description")
        ticket_priority = st.selectbox("Priority", ["Low", "Medium", "High"])
        
        if st.button("Submit Ticket"):
            if ticket_title and ticket_description:
                ticket_id = create_ticket(st.session_state.user["user_id"], ticket_title, ticket_description, ticket_priority)
                if ticket_id:
                    st.success("Ticket created successfully")
                    st.rerun()
            else:
                st.warning("Please provide both title and description")
    
    # Confirmation dialog for ticket deletion
    if st.session_state.confirm_delete:
        with st.container():
            st.warning(f"Are you sure you want to delete this ticket? This action cannot be undone.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, Delete"):
                    if delete_ticket(st.session_state.confirm_delete):
                        st.session_state.confirm_delete = None
                        st.success("Ticket deleted successfully")
                        st.rerun()
                    else:
                        st.error("Failed to delete ticket")
            with col2:
                if st.button("Cancel"):
                    st.session_state.confirm_delete = None
                    st.rerun()
    
    # List user tickets
    tickets = get_user_tickets(st.session_state.user["user_id"])
    
    if not tickets:
        st.info("You have no tickets yet")
    else:
        for ticket in tickets:
            col1, col2, col3, col4 = st.columns([3, 1, 0.5, 0.5])
            
            with col1:
                st.write(f"**{ticket['title']}**")
                st.write(f"Created: {ticket['created_at'].strftime('%Y-%m-%d %H:%M')}")
            
            with col2:
                priority_color = "blue" if ticket['priority'] == "Low" else "orange" if ticket['priority'] == "Medium" else "red"
                st.markdown(f"Priority: <span style='color:{priority_color}'>{ticket['priority']}</span>", unsafe_allow_html=True)
                
                status_color = "green" if ticket['status'] == "Closed" else "orange" if ticket['status'] == "In Progress" else "blue"
                st.markdown(f"Status: <span style='color:{status_color}'>{ticket['status']}</span>", unsafe_allow_html=True)
            
            with col3:
                if st.button("View", key=f"view_{ticket['ticket_id']}"):
                    select_ticket(ticket['ticket_id'])
                    st.rerun()
            
            with col4:
                if st.button("Delete", key=f"delete_{ticket['ticket_id']}"):
                    st.session_state.confirm_delete = ticket['ticket_id']
                    st.rerun()
            
            st.divider()

def show_admin_dashboard():
    st.title("Admin Dashboard")
    st.write(f"Logged in as: Admin ({st.session_state.user.get('email', 'Admin')})")
    
    if st.button("Logout", key="admin_logout_button"):
        logout()
        st.rerun()
    
    st.subheader("All Support Tickets")
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        status_filter = st.multiselect("Filter by Status", ["Open", "In Progress", "Closed"], default=["Open", "In Progress"])
    with col2:
        priority_filter = st.multiselect("Filter by Priority", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
    
    # List all tickets
    all_tickets = get_all_tickets()
    
    # Apply filters
    filtered_tickets = [t for t in all_tickets if t['status'] in status_filter and t['priority'] in priority_filter]
    
    # Confirmation dialog for ticket deletion
    if st.session_state.confirm_delete:
        with st.container():
            st.warning(f"Are you sure you want to delete this ticket? This action cannot be undone.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, Delete"):
                    if delete_ticket(st.session_state.confirm_delete):
                        st.session_state.confirm_delete = None
                        st.success("Ticket deleted successfully")
                        st.rerun()
                    else:
                        st.error("Failed to delete ticket")
            with col2:
                if st.button("Cancel"):
                    st.session_state.confirm_delete = None
                    st.rerun()
    
    if not filtered_tickets:
        st.info("No tickets match your filters")
    else:
        # Convert to DataFrame for better display
        df = pd.DataFrame(filtered_tickets)
        df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
        df = df.rename(columns={
            'created_at': 'Created',
            'title': 'Title',
            'status': 'Status',
            'priority': 'Priority',
            'user_email': 'User',
            'ticket_id': 'ID'
        })
        
        # Create clickable dataframe
        st.dataframe(df[['ID', 'Title', 'User', 'Status', 'Priority', 'Created']])
        
        # Ticket actions
        col1, col2, col3 = st.columns(3)
        with col1:
            ticket_id = st.selectbox("Select Ticket ID", options=[t["ticket_id"] for t in filtered_tickets])
        
        with col2:
            if st.button("View Selected Ticket"):
                select_ticket(ticket_id)
                st.rerun()
        
        with col3:
            if st.button("Delete Selected Ticket"):
                st.session_state.confirm_delete = ticket_id
                st.rerun()

def show_ticket_detail():
    # Get ticket details
    ticket = get_ticket_details(st.session_state.selected_ticket)
    
    if not ticket:
        st.error("Ticket not found")
        st.button("Back to Dashboard", on_click=lambda: navigate_to('dashboard'))
        return
    
    # Back button
    if st.button("← Back to Dashboard"):
        navigate_to('dashboard')
        st.rerun()
    
    # Ticket header
    st.title(f"Ticket: {ticket['title']}")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        priority_color = "blue" if ticket['priority'] == "Low" else "orange" if ticket['priority'] == "Medium" else "red"
        st.markdown(f"**Priority**: <span style='color:{priority_color}'>{ticket['priority']}</span>", unsafe_allow_html=True)
    
    with col2:
        status_color = "green" if ticket['status'] == "Closed" else "orange" if ticket['status'] == "In Progress" else "blue"
        st.markdown(f"**Status**: <span style='color:{status_color}'>{ticket['status']}</span>", unsafe_allow_html=True)
    
    with col3:
        st.write(f"**Submitted by**: {ticket['user_email']}")
    
    st.write(f"**Created**: {ticket['created_at'].strftime('%Y-%m-%d %H:%M')}")
    
    # Ticket description
    st.subheader("Description")
    st.write(ticket['description'])
    
    # Admin actions
    if st.session_state.user.get('is_admin', False):
        st.subheader("Admin Actions")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if ticket['status'] != 'In Progress' and st.button("Mark In Progress"):
                update_ticket_status(ticket['ticket_id'], "In Progress")
                st.rerun()
        
        with col2:
            if ticket['status'] != 'Closed' and st.button("Mark Closed"):
                update_ticket_status(ticket['ticket_id'], "Closed")
                st.rerun()
                
        with col3:
            if ticket['status'] != 'Open' and st.button("Reopen"):
                update_ticket_status(ticket['ticket_id'], "Open")
                st.rerun()
        
        with col4:
            if st.button("Delete Ticket"):
                st.session_state.confirm_delete = ticket['ticket_id']
                st.rerun()
    
    # Delete confirmation dialog
    if st.session_state.confirm_delete:
        with st.container():
            st.warning(f"Are you sure you want to delete this ticket? This action cannot be undone.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, Delete"):
                    if delete_ticket(st.session_state.confirm_delete):
                        st.session_state.confirm_delete = None
                        st.success("Ticket deleted successfully")
                        navigate_to('dashboard')
                        st.rerun()
                    else:
                        st.error("Failed to delete ticket")
            with col2:
                if st.button("Cancel"):
                    st.session_state.confirm_delete = None
                    st.rerun()
    
    # Messages
    st.subheader("Communication")
    messages = get_ticket_messages(ticket['ticket_id'])
    
    if not messages:
        st.info("No messages yet")
    else:
        for msg in messages:
            is_admin = msg['is_admin']
            col1, col2 = st.columns([1, 4])
            
            with col1:
                label = "Admin" if is_admin else "User"
                st.markdown(f"**{label}**")
                st.caption(f"{msg['created_at'].strftime('%Y-%m-%d %H:%M')}")
            
            with col2:
                st.markdown(f"{msg['content']}")
            
            st.divider()
    
    # New message form
    st.subheader("Add Reply")
    new_message = st.text_area("Your message")
    
    if st.button("Send Message"):
        if new_message:
            add_message(ticket['ticket_id'], st.session_state.user["user_id"], new_message)
            st.success("Message sent")
            st.rerun()
        else:
            st.warning("Please enter a message")

# Main app logic
def main():
    # Check if database tables exist, create them if they don't
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if tables exist
        cur.execute("SELECT EXISTS(SELECT * FROM information_schema.tables WHERE table_name='users')")
        users_exist = cur.fetchone()[0]
        
        if not users_exist:
            # Create tables
            conn.close()
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Users table
            cur.execute("""
                CREATE TABLE users (
                    user_id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tickets table
            cur.execute("""
                CREATE TABLE tickets (
                    ticket_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id),
                    title VARCHAR(255) NOT NULL,
                    description TEXT NOT NULL,
                    priority VARCHAR(50) CHECK (priority IN ('Low', 'Medium', 'High')),
                    status VARCHAR(50) CHECK (status IN ('Open', 'In Progress', 'Closed')) DEFAULT 'Open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Messages table
            cur.execute("""
                CREATE TABLE messages (
                    message_id SERIAL PRIMARY KEY,
                    ticket_id INTEGER REFERENCES tickets(ticket_id),
                    user_id INTEGER REFERENCES users(user_id),
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create an admin user
            admin_email = st.secrets.get("admin_credentials", {}).get("email", "admin@example.com")
            admin_password = st.secrets.get("admin_credentials", {}).get("password", "adminpassword")
            admin_password_hash = hash_password(admin_password)
            
            cur.execute(
                "INSERT INTO users (email, password_hash, is_admin) VALUES (%s, %s, TRUE)",
                (admin_email, admin_password_hash)
            )
            
            conn.commit()
            st.success("Database initialized successfully!")
        
        cur.close()
        conn.close()
    except Exception as e:
        st.error(f"Database initialization error: {e}")
    
    # Display appropriate page based on session state
    if st.session_state.user is None:
        show_login_page()
    else:
        if st.session_state.page == 'dashboard':
            if st.session_state.user.get('is_admin', False):
                show_admin_dashboard()
            else:
                show_user_dashboard()
        elif st.session_state.page == 'ticket_detail':
            show_ticket_detail()
        else:
            navigate_to('dashboard')
            st.rerun()

if __name__ == "__main__":
    main()