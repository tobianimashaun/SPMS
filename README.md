# SPMS
secure password management system

Overview -
A Python-based secure password management system designed to generate, encrypt, and safely store user passwords. The system ensures password confidentiality, integrity, and controlled access through modern encryption and authentication standards.


Key Features -
🔑 AES Encryption for password storage,
🧩 bcrypt Hashing for master password verification,
⚙️ Automatic Password Generation with customizable complexity,
💾 Secure Storage using an encrypted local database,
🧠 Password Retrieval System with authentication,
🧱 GUI Interface built with Tkinter for user interaction.


Tools & Technologies -
Language: Python,
Libraries: bcrypt, cryptography (AES), Tkinter, SQLite;
Security Concepts: Encryption, Hashing, Key Management, Authentication.


How It Works -
User creates a master password (hashed using bcrypt),
The app utilizes AES encryption to store generated passwords securely,
Users can add, view, or copy passwords through the GUI interface.


Future Enhancements - 
Integration of multi-factor authentication (MFA),
Option to sync encrypted passwords via cloud storage,
Enhanced key rotation and management features,
Stored data remains encrypted until accessed by the verified user.
