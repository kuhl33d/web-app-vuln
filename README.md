# w3bxAN Web Vulnerability Scanner

w3bxAN is a comprehensive web application vulnerability scanner with a Flask-based web interface. It helps identify security issues in web applications, including SQL injection, cross-site scripting (XSS), remote code execution (RCE), security misconfigurations, broken authentication, and cross-site request forgery (CSRF).

![w3bxAN Scanner](https://user-images.githubusercontent.com/79792270/229343852-5e982e48-443c-41db-93fd-c64be2341d96.png)

## Features

- **Comprehensive Vulnerability Detection**: Scans for SQL injection, XSS, RCE, security misconfigurations, broken authentication, and CSRF vulnerabilities
- **Web-based Interface**: User-friendly Flask web application for managing scans
- **User Authentication**: Secure login and registration with role-based access control
- **Scan Customization**: Configure scan settings based on specific requirements
- **Scheduled Scanning**: Set up automated scans to run hourly, daily, or weekly
- **Real-time Alerts**: Email notifications when vulnerabilities are detected
- **Detailed Reporting**: Comprehensive reports with visualizations and remediation recommendations
- **Historical Data Analysis**: Track vulnerability trends over time

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/w3bxAN.git
   cd w3bxAN
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables (optional but recommended for production):
   ```
   # For Windows
   set SECRET_KEY=your-secret-key
   set MAIL_USERNAME=your-email@example.com
   set MAIL_PASSWORD=your-email-password
   set MAIL_DEFAULT_SENDER=your-email@example.com
   
   # For Linux/Mac
   export SECRET_KEY=your-secret-key
   export MAIL_USERNAME=your-email@example.com
   export MAIL_PASSWORD=your-email-password
   export MAIL_DEFAULT_SENDER=your-email@example.com
   ```

## Usage

1. Start the Flask application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Register a new account or log in with the default admin credentials:
   - Username: admin
   - Password: admin

4. From the dashboard, you can:
   - Create new vulnerability scans
   - View scan results and detailed reports
   - Schedule recurring scans
   - Manage user accounts (admin only)

## Scan Results

After a scan is complete, the application will generate a comprehensive report that includes:

- The URL of the page that contains vulnerabilities
- The type of vulnerability detected (e.g., SQL injection, XSS, etc.)
- Detailed information about each vulnerability
- Recommended remediation actions
- Visualizations of vulnerability statistics

## Security Considerations

- Change the default admin password immediately after first login
- Use HTTPS in production environments
- Regularly update dependencies to patch security vulnerabilities
- Be cautious when scanning websites you don't own or have permission to test

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP for vulnerability classification and remediation guidelines
- Flask and its extensions for the web framework
- Plotly for data visualization
