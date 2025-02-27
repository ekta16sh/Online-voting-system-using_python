import sqlite3
import getpass
import hashlib

class VotingSystem:
    def __init__(self):
        self.conn = sqlite3.connect('voting_system.db')
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.options = ["Option 1", "Option 2", "Option 3"]
        self.logged_in_user = None
        self.admin_logged_in = False

    def hash_password(self, password):
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def create_tables(self):
        """Create tables if they don't exist."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS votes (
                option TEXT PRIMARY KEY,
                count INTEGER NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_votes (
               username TEXT,
               option TEXT,
               PRIMARY KEY (username, option),
               FOREIGN KEY (username) REFERENCES users(username),
               FOREIGN KEY (option) REFERENCES votes(option)
            )
        ''')
        
        self.conn.commit()

    def register_admin(self):
        """Register an admin user."""
        username = input("Admin username: ")
        password = getpass.getpass("Admin password: ")
        self.cursor.execute('INSERT INTO admin (username, password) VALUES (?, ?)', 
                            (username, self.hash_password(password)))
        self.conn.commit()
        print("Admin registered successfully.")

    def admin_login(self):
        """Log in as an admin."""
        username = input("Admin username: ")
        password = getpass.getpass("Admin password: ")
        hashed_password = self.hash_password(password)

        self.cursor.execute('SELECT password FROM admin WHERE username = ?', (username,))
        stored_password = self.cursor.fetchone()
        if stored_password and stored_password[0] == hashed_password:
            print("Admin login successful!")
            self.admin_logged_in = True
        else:
            print("Admin login failed!")
            self.admin_logged_in = False

    def register_user(self):
        """Register a new user with a username and password."""
        username = input("Choose a username: ")
        self.cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if self.cursor.fetchone():
            print("Username already exists.")
            return
        password = getpass.getpass("Choose a password: ")
        self.cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                            (username, self.hash_password(password)))
        self.conn.commit()
        print("User registered successfully.")

    def user_login(self):
        """Log in a user by checking their username and password."""
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        hashed_password = self.hash_password(password)

        self.cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        stored_password = self.cursor.fetchone()
        if stored_password and stored_password[0] == hashed_password:
            print("Login successful!")
            self.logged_in_user = username
        else:
            print("Login failed!")
            self.logged_in_user = None

    def show_options(self):
        """Display the voting options."""
        print("\nVoting Options:")
        for idx, option in enumerate(self.options, start=1):
            print(f"{idx}. {option}")

    def vote(self):
        """Cast a vote for one of the options."""
        if not self.logged_in_user:
            print("You need to log in first.")
            return

        self.show_options()
        try:
            choice = int(input("Choose an option by number: "))
            if 1 <= choice <= len(self.options):
                selected_option = self.options[choice - 1]
                # Check if the user has already voted
                self.cursor.execute('SELECT 1 FROM user_votes WHERE username = ? AND option = ?', 
                                (self.logged_in_user, selected_option))
                if self.cursor.fetchone():
                    print("You have already voted for this option.")
                    return

                # Update the vote count
                self.cursor.execute('SELECT count FROM votes WHERE option = ?', (selected_option,))
                result = self.cursor.fetchone()
                if result:
                  count = result[0] + 1
                  self.cursor.execute('UPDATE votes SET count = ? WHERE option = ?', (count, selected_option))
                else:
                   self.cursor.execute('INSERT INTO votes (option, count) VALUES (?, ?)', (selected_option, 1))
            
                # Record the user's vote
                self.cursor.execute('INSERT INTO user_votes (username, option) VALUES (?, ?)', (self.logged_in_user, selected_option))
                self.conn.commit()
                print(f"Voted for {selected_option}")
            else:
                print("Invalid choice!")
        except ValueError:
            print("Invalid input! Please enter a number.")


    def show_results(self):
        """Display the voting results."""
        print("\nVoting Results:")
        self.cursor.execute('SELECT option, count FROM votes')
        results = self.cursor.fetchall()
        for option, count in results:
            print(f"{option}: {count} votes")

    def view_all_users(self):
        """View all registered users."""
        self.cursor.execute('SELECT username FROM users')
        users = self.cursor.fetchall()
        print("\nAll Users:")
        for user in users:
            print(user[0])
    def delete_user(self):
        """Delete a user."""
        if not self.admin_logged_in:
            print("You need to be logged in as an admin to delete a user.")
            return

        username = input("Enter the username of the user to delete: ")
        self.cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if self.cursor.fetchone():
            self.cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            self.cursor.execute('DELETE FROM votes WHERE option IN (SELECT option FROM votes WHERE option = ?)', (username,))
            self.conn.commit()
            print(f"User '{username}' deleted successfully.")
        else:
            print("User not found.")

    def close(self):
        """Close the database connection."""
        self.conn.close()

def main():
    system = VotingSystem()

    while True:
        if system.admin_logged_in:
            print("\nAdmin Panel:")
            print("1. Register User")
            print("2. View All Users")
            print("3. View Results")
            print("4. Delete User")
            print("5. Logout")
            choice = input("Enter your choice: ")
            if choice == '1':
                system.register_user()
            elif choice == '2':
                system.view_all_users()
            elif choice == '3':
                system.show_results()
            elif choice == '4':
                system.delete_user()
            elif choice == '5':
                system.admin_logged_in = False
                print("Logged out of admin panel.")
            else:
                print("Invalid choice!")

        else:
            print("1. Admin Login")
            print("2. Login")
            print("3. Vote")
            print("4. Exit")

            choice = input("Enter your choice: ")

            if choice == '102':
                system.register_admin()
            elif choice == '1':
                system.admin_login()
            elif choice == '2':
                system.user_login()
            elif choice == '3':
                system.vote()
            elif choice == '4':
                system.close()
                break
            else:
                print("Invalid choice!")

if __name__ == "__main__":
    main()
