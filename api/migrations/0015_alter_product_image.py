# Generated by Django 5.1.2 on 2024-11-14 07:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_remove_customuser_is_super_admin_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='image',
            field=models.TextField(blank=True, null=True),
        ),
    ]
