# Generated by Django 4.2.5 on 2023-10-07 05:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Home', '0003_user_login_token'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='username_reset_token',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
    ]
