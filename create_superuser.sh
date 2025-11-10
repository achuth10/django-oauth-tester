#!/bin/bash
# Script to create superuser for Django OAuth project

echo "Creating superuser for Django OAuth project..."
echo "Default credentials: admin / admin123"
echo ""

source venv/bin/activate

# Create superuser with predefined credentials (for testing only)
python manage.py shell << EOF
from django.contrib.auth.models import User

if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='admin123',
        first_name='Admin',
        last_name='User'
    )
    print("✓ Superuser 'admin' created successfully!")
else:
    print("✓ Superuser 'admin' already exists")
EOF

echo ""
echo "You can now access:"
echo "  - Django Admin: http://localhost:8000/admin/"
echo "  - Username: admin"
echo "  - Password: admin123"
