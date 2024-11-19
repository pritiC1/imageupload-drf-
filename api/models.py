from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.conf import settings
from django.contrib.auth import get_user_model



class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=10, null=True)
    middle_name = models.CharField(max_length=100, null=True)
    gender = models.CharField(max_length=10, null=True)
    email = models.EmailField(unique=True)
    contact_number = models.CharField(max_length=15, null=True)
    dob = models.DateField(null=True, blank=True)
    otp_code = models.CharField(max_length=6, blank=True, null=True)  # Add otp_code here
    otp_verified = models.BooleanField(default=False)
    

    # Adding custom related_name to avoid clashes
    groups = models.ManyToManyField(Group, related_name='custom_user_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_set', blank=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'contact_number', 'email', 'dob']

    def __str__(self):
        return self.username

class OTP(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)  # Set default value to False
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='products/', null=True, blank=True)
    image_url = models.URLField(max_length=2048, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    like_count = models.IntegerField(default=0)
    liked_by = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='liked_products', blank=True)
    
class Cart(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cart')
    products = models.JSONField(default=list)  # Store products as a list of dictionaries
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart of {self.user.username}"
    
    def add_product(self, product_id, quantity):
        # Add or update product in the cart
        for item in self.products:
            if item['product_id'] == product_id:
                item['quantity'] += quantity
                self.save()
                return
        # If product doesn't exist in the cart, add new item
        self.products.append({'product_id': product_id, 'quantity': quantity})
        self.save()

    def remove_product(self, product_id):
        # Remove product from cart
        self.products = [item for item in self.products if item['product_id'] != product_id]
        self.save()

    def update_quantity(self, product_id, quantity):
        # Update the quantity of a product in the cart
        for item in self.products:
            if item['product_id'] == product_id:
                item['quantity'] = quantity
                self.save()
                return
            

class Like(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    
    class Meta:
        unique_together = ('user', 'product')



class Order(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    products = models.ManyToManyField(Product)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order {self.id} by {self.user.username}"