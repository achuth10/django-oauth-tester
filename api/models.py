"""
Django models for the API app.

Models:
    - Contract: Represents a contract document with scoped access control
"""
from django.db import models
from django.contrib.auth.models import User


class Contract(models.Model):
    """
    Contract model for demonstrating OAuth2 scoped access.

    Scopes:
        - contracts:read - View contract information
        - contracts:write - Create and update contracts
        - contracts:delete - Delete contracts

    Fields:
        - title: Contract title
        - description: Contract description
        - content: Full contract text
        - owner: User who owns the contract
        - created_at: Timestamp when created
        - updated_at: Timestamp when last updated
        - status: Contract status (draft, active, completed, cancelled)
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    content = models.TextField()
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='contracts'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['owner', 'status']),
        ]

    def __str__(self):
        return f"{self.title} ({self.status})"

    def __repr__(self):
        return f"<Contract: {self.title} - {self.owner.username}>"
