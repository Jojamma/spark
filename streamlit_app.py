import streamlit as st
import pandas as pd
from datetime import datetime

# Hardcoded credentials for demonstration (use a secure method in production)
USER_CREDENTIALS = {
    "user1": "user@123",
    "user2": "user2@123",
    "user3": "user3@123"
}
ADMIN_CREDENTIALS = {
    "admin": "admin@123"
}

# Initialize session states if they don't exist
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'active_users' not in st.session_state:
    st.session_state.active_users = []  # To track active users and timestamps

if 'log_data' not in st.session_state:
    st.session_state.log_data = []

# Function to check credentials
def check_credentials(username, password):
    return (username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password) or \
           (username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password)

# Login page logic
if not st.session_state.logged_in:
    st.title("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if check_credentials(username, password):
            st.session_state.logged_in = True
            st.session_state.is_admin = username in ADMIN_CREDENTIALS  # Set admin status based on username
            
            # Log the active user with timestamp
            if username not in [user['username'] for user in st.session_state.active_users]:
                st.session_state.active_users.append({
                    'username': username,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid username or password.")
else:
    # Check if the user is admin or regular user
    if st.session_state.is_admin:
        # Admin view: Empty page
        st.title("Admin Dashboard")
        st.write("Welcome to the Admin Dashboard. This page is intentionally left blank.")
        
        # Logout button for admin
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.is_admin = False  # Reset admin status
            st.experimental_rerun()  # Refresh the app to show the login page

    else:
        # Regular user view: Sidebar for navigation
        st.sidebar.title("Navigation")
        page = st.sidebar.radio("Go to", ["Dashboard", "Log Page"])

        if page == "Dashboard":
            st.title("Dataset Uploader and Model Selector")

            # File uploader for dataset
            uploaded_file = st.file_uploader("Upload your dataset (supports large files up to 50GB)", type=["csv"])

            model_type = st.selectbox("Select Model Type:", ["Transformer", "CNN", "RNN", "ANN"])
            core_option = st.selectbox("Select Core Option:", ["CPU", "GPU", "HDFS"])

            run_button_clicked = st.button("Run")

            if run_button_clicked:
                if uploaded_file is None:
                    st.error("Please upload a valid file before running.")
                else:
                    dataset_size = uploaded_file.size  # Get size of the uploaded file in bytes
                    dataset_name = uploaded_file.name

                    try:
                        # Read and display dataset columns
                        if uploaded_file.name.endswith('.csv'):
                            df = pd.read_csv(uploaded_file)
                            st.write("### Columns in the Dataset")
                            st.write(list(df.columns))
                        else:
                            st.error("Unsupported file type. Please upload a CSV file.")

                        # Display dataset details
                        st.write(f"**Dataset Name:** {dataset_name}")
                        st.write(f"**Dataset Size:** {dataset_size / (1024 * 1024):.2f} MB")

                        # Display core option
                        st.write("### Core Used")
                        st.write(core_option)

                        # Display model type and features
                        st.write("### Model Type")
                        st.write(model_type)

                        # Display model features based on selection
                        features = {
                            "Transformer": ["Epoch", "Batch Size", "Iteration", "Learning Rate", "Attention Mechanism"],
                            "CNN": ["Epoch", "Batch Size", "Iteration", "Learning Rate", "Convolutional Layers"],
                            "RNN": ["Epoch", "Batch Size", "Iteration", "Learning Rate", "Hidden States"],
                            "ANN": ["Epoch", "Batch Size", "Iteration", "Learning Rate", "Activation Functions"]
                        }
                        
                        for feature in features[model_type]:
                            st.write(f"- {feature}")

                        # Log details into session state with username tracking
                        new_log = {
                            "Username": username,
                            "Dataset Name": dataset_name,
                            "Dataset Size": f"{dataset_size / (1024 * 1024):.2f} MB",
                            "Model": model_type,
                            "CPU": "Used" if core_option == "CPU" else "Not Used",
                            "GPU": "Used" if core_option == "GPU" else "Not Used",
                            "HDFS": "Used" if core_option == "HDFS" else "Not Used",
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        st.session_state.log_data.insert(0, new_log)  # Insert at the start for recent-first ordering

                        st.success("Run executed and details logged successfully!")

                    except Exception as e:
                        st.error(f"Error processing the uploaded file: {e}")

        elif page == "Log Page":
            st.title("Log Page")

            # Display Log Table
            if st.session_state.log_data:
                log_df = pd.DataFrame(st.session_state.log_data)
                log_df.set_index('Timestamp', inplace=True)
                st.dataframe(log_df)

                # Option to download the log data as CSV
                csv = log_df.to_csv(index=True).encode('utf-8')
                st.download_button(
                    label="Download Log as CSV",
                    data=csv,
                    file_name='log_data.csv',
                    mime='text/csv',
                    key='download-csv'
                )
            else:
                st.info("No logs available yet.")

            # Disclaimer about log data at the bottom of the page
            st.warning("**Disclaimer:** The log results will not be saved once you log out. Please download the log data if you wish to keep a record.")
