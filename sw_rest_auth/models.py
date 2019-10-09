# coding: utf-8
from django.contrib.auth import get_user_model
from django.db import models
from django.contrib.auth.models import Group

User = get_user_model()


class Permission(models.Model):
    code = models.CharField(max_length=50, unique=True, help_text='code for using in permission class in program code')
    name = models.CharField(max_length=100, unique=True, help_text='human permission name')
    description = models.TextField(blank=True, help_text='detailed description')

    class Meta:
        ordering = ('code', )

    def __str__(self):
        return '{0} ({1})'.format(self.name, self.code)


class UserPermission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'permission')
        ordering = ('user__username', 'permission__code')

    def __str__(self):
        return '{0} - {1}'.format(self.user, self.permission)


class GroupPermission(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('group', 'permission')
        ordering = ('group__name', 'permission__code')

    def __str__(self):
        return '{0} - {1}'.format(self.group, self.permission)
