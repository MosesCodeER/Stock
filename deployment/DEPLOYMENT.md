# Stock Tracker Application Deployment Guide

This guide provides instructions for deploying the Stock Tracker Application to a production environment.

## Prerequisites

- Ubuntu 20.04 or newer
- Python 3.8 or newer
- Nginx
- Let's Encrypt for SSL certificates
- Domain name pointing to your server

## Installation Steps

1. **Update system packages**

   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **Install required packages**

   ```bash
   sudo apt install -y python3-pip python3-venv nginx certbot python3-certbot-nginx
   ```

3. **Create application directory**

   ```bash
   sudo mkdir -p /var/www/stock-tracker
   sudo chown -R $USER:$USER /var/www/stock-tracker
   ```

4. **Copy application files**

   ```bash
   cp -r * /var/www/stock-tracker/
   ```

5. **Set up Python virtual environment**

   ```bash
   cd /var/www/stock-tracker
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

6. **Set environment variables**

   Create a .env file in the application directory:

   ```bash
   cat > /var/www/stock-tracker/.env << EOL
   SECRET_KEY=49c9782dd62370b83b9a1eac0ea34fe8805a4402b2e9206d
   CSRF_SECRET_KEY=f9466784c841c574353ede1a3a078e09173b9630c4130b9e
   DATABASE_URL=sqlite:///production.db
   EOL
   ```

7. **Initialize the database**

   ```bash
   cd /var/www/stock-tracker
   source venv/bin/activate
   python init_db.py
   ```

8. **Set up Nginx**

   ```bash
   sudo cp stock-tracker.nginx /etc/nginx/sites-available/stock-tracker
   sudo ln -s /etc/nginx/sites-available/stock-tracker /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

9. **Set up SSL certificate**

   ```bash
   sudo certbot --nginx -d stock-tracker.example.com
   ```

10. **Set up systemd service**

    ```bash
    sudo cp stock-tracker.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable stock-tracker
    sudo systemctl start stock-tracker
    ```

11. **Check application status**

    ```bash
    sudo systemctl status stock-tracker
    ```

## Security Notes

- The default admin credentials are:
  - Email: admin@example.com
  - Password: persona101!
  
  **IMPORTANT**: Change the admin password immediately after first login!

- All sensitive data is encrypted in the database
- HTTPS is enforced for all connections
- Security headers are set to protect against common web vulnerabilities
- Comprehensive logging is enabled in the logs directory

## Maintenance

- Logs are stored in /var/www/stock-tracker/logs
- Database file is at /var/www/stock-tracker/production.db
- To update the application, replace the files and restart the service:
  ```bash
  sudo systemctl restart stock-tracker
  ```

## Troubleshooting

- Check application logs: `tail -f /var/www/stock-tracker/logs/*.log`
- Check systemd logs: `sudo journalctl -u stock-tracker`
- Check Nginx logs: `sudo tail -f /var/log/nginx/error.log`
