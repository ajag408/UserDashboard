# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2018-09-14 19:59
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('comment', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=50)),
                ('last_name', models.CharField(max_length=50)),
                ('email', models.CharField(max_length=100)),
                ('pw_hash', models.CharField(max_length=150)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('description', models.TextField()),
                ('user_level', models.CharField(max_length=7)),
            ],
        ),
        migrations.AddField(
            model_name='message',
            name='message_user_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='first_app.User'),
        ),
        migrations.AddField(
            model_name='message',
            name='user_profile_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_profile_messages', to='first_app.User'),
        ),
        migrations.AddField(
            model_name='comment',
            name='comment_user_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='first_app.User'),
        ),
        migrations.AddField(
            model_name='comment',
            name='message_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='message_comments', to='first_app.Message'),
        ),
    ]
