"""
Django Admin Configuration

Registers models for administration through Django's admin interface:
- Contract model with custom list display and filters

Note: OAuth2 models (Application, AccessToken, etc.) are automatically
registered by django-oauth-toolkit and can be managed through the admin.
"""
from django.contrib import admin
from .models import Contract


@admin.register(Contract)
class ContractAdmin(admin.ModelAdmin):
    """
    Admin interface for Contract model.

    Features:
        - Search by title, description, content
        - Filter by status, owner, creation date
        - Display key fields in list view
        - Read-only timestamps
    """
    list_display = ('title', 'owner', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('title', 'description', 'content', 'owner__username')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)

    fieldsets = (
        ('Contract Information', {
            'fields': ('title', 'description', 'content', 'status')
        }),
        ('Ownership', {
            'fields': ('owner',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
