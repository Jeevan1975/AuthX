from django.contrib import admin
from . models import User, ResetToken

# Register your models here.

admin.site.register(User)
admin.site.register(ResetToken)