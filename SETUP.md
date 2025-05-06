# w3bxAN Web Vulnerability Scanner - Setup Guide

This guide will help you set up and run the w3bxAN Web Vulnerability Scanner on your system.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Git (optional, for cloning the repository)

## Installation Steps

### 1. Get the Code

Either clone the repository or download and extract the ZIP file:

```bash
# Option 1: Clone with Git
git clone https://github.com/yourusername/w3bxAN.git
cd w3bxAN

# Option 2: Download ZIP and extract
# Then navigate to the extracted directory
```

### 2. Install Dependencies

Install all required packages using pip:

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root directory by copying the example file:

```bash
# For Windows
copy .env.example .env

# For Linux/Mac
cp .env.example .env
```

Edit the `.env` file and update the values as needed:

```
SECRET_KEY=your-secret-key-here
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=your-email@example.com
```

### 4. Initialize the Database

The database will be automatically created when you first run the application.

### 5. Run the Application

Start the Flask application using the provided run script:

```bash
python run.py
```

Alternatively, you can run the main app file directly:

```bash
python app.py
```

### 6. Access the Web Interface

Open your web browser and navigate to:

```
http://localhost:5000
```

### 7. First Login

Log in with the default admin credentials:
- Username: `admin`
- Password: `admin`

**Important:** Change the default admin password immediately after your first login for security reasons.

## Troubleshooting

### Common Issues

1. **Port already in use**
   - Change the port by setting the PORT environment variable:
     ```
     # In .env file
     PORT=5001
     ```

2. **Email sending fails**
   - Verify your email credentials in the .env file
   - For Gmail, you may need to enable "Less secure app access" or use an App Password

3. **Database errors**
   - If you encounter database issues, try deleting the `vulnerability_scanner.db` file and restart the application to recreate it

## Running in Production

For production environments, consider the following:

1. Use a production WSGI server like Gunicorn or uWSGI
2. Set up HTTPS using a reverse proxy like Nginx
3. Use a production-grade database like PostgreSQL
4. Disable debug mode by setting `FLASK_DEBUG=False` in your .env file

## Need Help?

If you encounter any issues or have questions, please open an issue on the GitHub repository.