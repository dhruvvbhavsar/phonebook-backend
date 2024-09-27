# Phonebook Application

## Overview

This Phonebook Application is a modern, containerized web service that allows users to manage contacts, mark spam numbers, and search for contact information. It's built with Flask and uses MySQL for persistent storage and Redis for caching.

Key Features:
- User registration and authentication
- Contact management (add, view, delete contacts)
- Spam reporting and likelihood calculation
- Global contact search
- Email verification for new users

## Tech Stack

- Backend: Python (Flask)
- Database: MySQL
- Caching: Redis
- Containerization: Docker
- Reverse Proxy: Nginx (for production deployments)

## Prerequisites

To run this application, you need to have the following installed on your system:
- Docker
- Docker Compose
- Git

## Local Development Setup

Follow these steps to set up the project for local development:

1. Clone the repository:
   ```
   git clone https://github.com/dhruvvbhavsar/phonebook-backend
   cd phonebook-backend
   ```

2. Create a `.env` file in the root directory with the following content:
   ```
   EMAIL_ADDRESS=no-reply@picostone.com
   EMAIL_PASSWORD=Noreply@123
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   MYSQL_ROOT_PASSWORD=ultra-secure
   FLASK_SECRET_KEY=spinnaker
   MYSQL_USER=dhruv
   MYSQL_PASSWORD=batman
   MYSQL_DATABASE=phonebook
   ```
   Note: Replace these placeholder values with your actual configuration.

3. Build and start the Docker containers:
   ```
   docker-compose up --build
   ```

4. The application should now be running at `http://localhost:5000`

5. To stop the application, use:
   ```
   docker-compose down
   ```

## Database Setup

The database schema is automatically initialized when the MySQL container is first created, using the `init.sql` file in the project root.

## API Endpoints

(Here, you would list and briefly describe your API endpoints. For example:)

- `POST /register`: Register a new user
- `POST /login`: Authenticate a user
- `GET /contacts`: Retrieve user's contacts
- `POST /add-contact`: Add a new contact
- `POST /mark-spam`: Mark a number as spam
- `GET /search`: Search for contacts

## Production Deployment

For production deployment instructions, please refer to the `DEPLOYMENT.md` file in this repository.

## Contributing

We welcome contributions to this project. Please fork the repository and submit a pull request with your changes.

## Troubleshooting

If you encounter any issues during setup or running the application, please check the following:

1. Ensure all required ports (5000, 3306, 6379) are free on your local machine.
2. If you have permission issues with MySQL, you may need to change the ownership of the mysql_data volume:
   ```
   sudo chown -R 999:999 ./mysql_data
   ```
3. If the web service fails to connect to MySQL, it might be because MySQL is still initializing. Wait a moment and restart the web service:
   ```
   docker-compose restart web
   ```

For any other issues, please open an issue in the GitHub repository.
