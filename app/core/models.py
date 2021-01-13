import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
                                    PermissionsMixin
from django.conf import settings
from django.utils import timezone


class UserManager(BaseUserManager):

    # password=None incase I want to create user
    # that is not active, that does not have password
    # take any of the extra arguments passed in
    def create_user(self, email, password=None, **extra_fields):
        # Creates and saves a new user"""
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        # This is here because we have to hash it
        user.set_password(password)
        # this can be used when multiple databases are being used
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        # Creates and saves a new super user"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    # Custom user model that supports using email instead of username"""

    ADMIN = 1
    ELITE = 2
    NOOB = 3

    ROLE_CHOICES = (
        (ADMIN, 'Admin'),
        (ELITE, 'Elite'),
        (NOOB, 'Noob')
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=3)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)


    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email
