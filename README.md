# Description
This project is a simple Flask app with main focus on safety. Functionality and UI were second priority.
# Features
- Negative Validation of user inputs
- Tracking of login attempts and enforcement of delays
- CSRF protection
- Secure password reset via email
- System monitoring for new logins
- Blocking excessive requests to certain endpoints to prevent abuse and ensure system stability
- Content Security Policy (CSP) implementation
# Deployment
Use:
`docker-compose up --build`
On Linux you can also use script:
`prepare_and_compose_docker.sh`
# TODO
- User-side validation
- Proper ailing system
