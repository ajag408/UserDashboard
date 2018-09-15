from __future__ import unicode_literals
import re, bcrypt
from django.db import models
from django.db.models import Count
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# Create your models here.
class UserManager(models.Manager):


    def check_first_name(self, first_name):
        if len(first_name)<2 or first_name.isalpha() is False:
            return False
        else:
            return True

    def check_last_name(self, last_name):
        if len(last_name)<2 or last_name.isalpha() is False:
            return False
        else:
            return True

    def check_email_1(self, email):
        if not EMAIL_REGEX.match(email):
            return False
        else:
            return True

    def check_email_2(self,email):
        users = User.objects.all()
        for user in users:
            if user.email == email:
                return False

        return True

    def check_password_1(self,password):
        if len(password)<8:
            return False
        else:
            return True

    def check_password_2(self,password,pconf):
        if pconf != password:
            return False
        else:
            return True


    def register(self, first_name, last_name, email, password, pconf):
        query_reg_check = User.objects.filter(email=email).values('email').annotate(Count('email'))
        if query_reg_check:
            if query_reg_check[0]['email'] == email:
                return False
        elif len(first_name) >= 2 and first_name.isalpha() and len(last_name) >= 2 and last_name.isalpha() and EMAIL_REGEX.match(email) and len(password) >= 8 and password == pconf:
            password = password.encode()

            pw_hash = bcrypt.hashpw(password, bcrypt.gensalt())

            new_user = User.objects.create(first_name = first_name, last_name = last_name, email = email, pw_hash = pw_hash)
            if new_user.id == 1:
                new_user.user_level = 'admin'
                new_user.save()
            else:
                new_user.user_level = 'normal'
                new_user.save()
            return True

    def login(self, email, password):
        # check_user = User.objects.filter(email = email)
        query_e = User.objects.filter(email=email).values('email').annotate(Count('pw_hash'))
        query_p = User.objects.filter(email=email).values('pw_hash').annotate(Count('pw_hash'))
        email_check = False
        password_check = False
        if EMAIL_REGEX.match(email) and len(query_e) > 0:
            if query_e[0]['email'] == email:
                email_check = True
                check_pw = query_p[0]['pw_hash']
                password = password.encode()
                check_pw = check_pw.encode()
                if bcrypt.hashpw(password, check_pw) == check_pw:
                    password_check = True
        if email_check and password_check:
            return True

class User(models.Model):
    first_name = models.CharField(max_length = 50)
    last_name = models.CharField(max_length = 50)
    email = models.CharField(max_length = 100)
    pw_hash = models.CharField(max_length =150)
    created_at = models.DateTimeField(auto_now_add = True)
    description = models.TextField()
    user_level = models.CharField(max_length = 7)
    objects = UserManager()
    def __repr__(self):
        return "<User object: {} {} {} {}>".format(self.first_name, self.last_name, self.email, self.user_level)


class Message(models.Model):
    message_user_id = models.ForeignKey(User)
    user_profile_id = models.ForeignKey(User, related_name = 'user_profile_messages')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

class Comment(models.Model):
    message_id = models.ForeignKey(Message, related_name = 'message_comments')
    comment_user_id = models.ForeignKey(User)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
