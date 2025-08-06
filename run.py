#!/usr/bin/env python3
"""
Whistleblower Portal - Run Script
Simple script to start the Flask application
"""

from app import app, init_db

if __name__ == '__main__':
    print("Starting Whistleblower Portal...")
    print("Access the application at: http://localhost:5050")
    print("Admin login at: http://localhost:5050/admin/login")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5050) 