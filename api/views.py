from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
import random
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, OTP
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
import logging 
from django.views import View
from rest_framework import status
from .models import Product
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import models
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Product
from django.shortcuts import get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from .models import OTP, CustomUser
from .models import Cart
from rest_framework_simplejwt.authentication import JWTAuthentication


logger = logging.getLogger(__name__)


class HomePage(APIView):
    def get(self, request):
        data = {
            # "welcome_message": "Welcome to My E-commerce Store",
            "features": [
                "Task Management",
                "User Authentication",
                "Product Upload"
            ],
            "latest_products": [
                {"name": "Product 1", "price": 99},
                {"name": "Product 2", "price": 199}
            ]
        }
        return Response(data, status=status.HTTP_200_OK)


logger = logging.getLogger(__name__)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        print("Request data:", request.data)

        # Extract data from the request
        username = request.data.get('username')
        first_name = request.data.get('first_name')
        middle_name = request.data.get('middle_name')
        last_name = request.data.get('last_name')
        gender = request.data.get('gender')
        email = request.data.get('email')
        contact_number = request.data.get('contact_number')
        dob = request.data.get('dob')
        password = request.data.get('password')

        # Validate that required fields are present
        required_fields = ['username', 'first_name', 'email', 'middle_name', 'last_name', 'contact_number', 'date_of_birth', 'password']
        for field in required_fields:
            if not request.data.get(field):
                return Response({f'error': f'{field} is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Create the new user
        try:
            user = CustomUser.objects.create_user(
                username=username,
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                gender=gender,
                email=email,
                contact_number=contact_number,
                dob=dob,
                password=password , # Make sure to call set_password on the instance
                otp_verified = False,
            )
            user.set_password(password)
            user.save()
            # Generate OTP after successful registration
            otp_code = str(random.randint(100000, 999999))
            otp_instance = OTP.objects.create(user=user, otp_code=otp_code)

            # Send OTP email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            # Send success response for registration
            response_data = {
                'message': 'Registration successful. Redirecting to OTP verification...',
                'user_id': user.id
            }
            user.save()
            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return Response({'error': 'Registration failed. Please try again.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


logger = logging.getLogger(__name__)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        print(f"Received request data: {request.data}") 
        # Retrieve only the otp_code from the request
        username = request.data.get('username')
        otp = request.data.get('otp_code')


        print(f"Received OTP: {otp}")

        # Validate input
        if not username or not otp:
            logger.warning("Validation failed: Username and OTP are required.")
            return Response({"error": "Username and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)
        # Fetch the OTP record based on the OTP code
        try:
            user = CustomUser.objects.get(username=username)
            otp_record = OTP.objects.get(otp_code=otp)

            if otp_record.is_verified:
                logger.info(f"OTP already verified.")
                return Response({"error": "OTP has already been verified."}, status=status.HTTP_400_BAD_REQUEST)

        except (CustomUser.DoesNotExist, OTP.DoesNotExist):
            logger.warning("Invalid username or OTP.")
            return Response({"error": "Invalid username or OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark the OTP as verified
        otp_record.otp_verified = True
        otp_record.save()


        logger.info("OTP verified successfully.")
        return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        otp_code = request.data.get('otp')  # Assuming OTP is passed in the request

        print(f"Received login attempt - Username: {username}")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        print(f"User found: {user.username}")

        # Check password and OTP verification status
        if user.check_password(password):
            # Verify OTP if required
            if not user.otp_verified and user.otp_code == otp_code:
                user.otp_verified = True
                user.save()
                print("OTP verified and user status updated.")

            # Generate tokens only if user is verified
            if user.otp_verified:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                
                # Store tokens in the database (optional)
                user.refresh_token = str(refresh)  # Save refresh token
                user.access_token = access_token  # Save access token (optional)
                user.save()

                return Response({
                    "refresh": str(refresh),
                    "access": access_token,
                    "message": "Login successful."
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "User not verified. Invalid OTP."}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Invalid credentials or user not verified."}, status=status.HTTP_401_UNAUTHORIZED)
        
class ProductView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can access

    def has_super_admin_access(self, request):
        # Check if the user is a super admin
        return request.user.is_superuser

    
        
    def get(self, request, pk=None):
        if pk:
            product = get_object_or_404(Product, pk=pk)
            data = {
                "id": product.id,
                "name": product.name,
                "description": product.description,
                "price": product.price,
                "brand": product.brand,
                "category": product.category,
                "color": product.color,
                "size": product.size,
               
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            products = Product.objects.all()
            data = [
                {
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "brand": product.brand,
                    "category": product.category,
                    "color": product.color,
                    "size": product.size,
                    
                }
                for product in products
            ]
            return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        product = Product.objects.create(
            name=data.get("name"),
            description=data.get("description"),
            price=data.get("price"),
            brand=data.get("brand"),
            category=data.get("category"),
            color=data.get("color"),
            size=data.get("size"),
            
        )
        return Response({"id": product.id, "message": "Product created successfully!"}, status=status.HTTP_201_CREATED)

    def put(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        data = request.data
        product.name = data.get("name", product.name)
        product.description = data.get("description", product.description)
        product.price = data.get("price", product.price)
        product.brand = data.get("brand", product.brand)
        product.category = data.get("category", product.category)
        product.color = data.get("color", product.color)
        product.size = data.get("size", product.size)
        product.save()
        return Response({"message": "Product updated successfully!"}, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        product.delete()
        return Response({"message": "Product deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)


class ProductCreateView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated

    def post(self, request):
        data = request.data
        required_fields = ['name', 'description', 'price', 'brand', 'category', 'color', 'size']
        for field in required_fields:
            if field not in data:
                return Response({f"{field}": "This field is required."}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Request user: {request.user}, Authenticated: {request.user.is_authenticated}")

        if not request.user or not request.user.is_authenticated:
            return Response({"error": "User must be authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

        image = request.FILES.get('image')

        # Create the product in the database
        try:
            # Create product with owner set to the current authenticated user
            product = Product.objects.create(
                name=data['name'],
                description=data['description'],
                price=data['price'],
                brand=data['brand'],
                category=data['category'],
                color=data['color'],
                size=data['size'],
                owner=request.user , # Set the owner to the current user
                image=image
            )

            print(f"Product created successfully with owner: {product.owner.username}")
            return Response({
                "message": "Product uploaded successfully!",
                "product": {
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "brand": product.brand,
                    "category": product.category,
                    "color": product.color,
                    "size": product.size,
                    "created_at": product.created_at,
                    "updated_at": product.updated_at,
                    "image_url": product.image.url if product.image else None 
                    
                }
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Error creating product: {str(e)}")
            return Response({"error": "Failed to create product."}, status=status.HTTP_400_BAD_REQUEST)
        

class ProductListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        try:
            # Fetch all products owned by the authenticated user
            products = Product.objects.filter(owner=request.user)

            # If no products found, return a message
            if not products:
                return Response({"message": "No products found."}, status=status.HTTP_404_NOT_FOUND)

            # Manually construct the response data (without serializers)
            product_data = []
            for product in products:
                product_data.append({
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "brand": product.brand,
                    "category": product.category,
                    "color": product.color,
                    "size": product.size,
                    "created_at": product.created_at,
                    "updated_at": product.updated_at,
                    
                })

            return Response({"products": product_data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving products: {str(e)}")
            return Response({"error": "Failed to retrieve products."}, status=status.HTTP_400_BAD_REQUEST)
        
class PublicProductListView(APIView):
    """
    This view is used to fetch all products publicly for the homepage.
    No authentication required.
    """

    def get(self, request):
        try:
            # Fetch all products (no filtering by user)
            products = Product.objects.all()

            # If no products found, return a message
            if not products:
                return Response({"message": "No products found."}, status=status.HTTP_404_NOT_FOUND)

            # Manually construct the response data (without serializers)
            product_data = []
            for product in products:
                product_data.append({
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "brand": product.brand,
                    "category": product.category,
                    "color": product.color,
                    "size": product.size,
                    "created_at": product.created_at,
                    "updated_at": product.updated_at,
                    "image_url": product.image.url if product.image else None,  # Assuming the model has an image field
                })

            return Response({"products": product_data}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving products: {str(e)}")
            return Response({"error": "Failed to retrieve products."}, status=status.HTTP_400_BAD_REQUEST)
        
class AddToCartView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        # Basic data validation
        if not product_id or not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        product = get_object_or_404(Product, id=product_id)
        
        # Retrieve or create the user's cart
        cart, created = Cart.objects.get_or_create(user=request.user)

        # Add the product to the cart
        cart.add_product(product_id=product.id, quantity=quantity)

        return Response({
            "message": "Product added to cart",
            "cart": cart.products
        }, status=status.HTTP_201_CREATED)


class UpdateCartItemView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, product_id):
        quantity = request.data.get("quantity")

        # Basic data validation
        if not isinstance(quantity, int) or quantity <= 0:
            return Response({"error": "Invalid quantity"}, status=status.HTTP_400_BAD_REQUEST)

        cart = get_object_or_404(Cart, user=request.user)

        # Update the quantity of the product in the cart
        cart.update_quantity(product_id=product_id, quantity=quantity)

        return Response({
            "message": "Cart item updated",
            "cart": cart.products
        }, status=status.HTTP_200_OK)


class RemoveFromCartView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, product_id):
        cart = get_object_or_404(Cart, user=request.user)

        # Remove the product from the cart
        cart.remove_product(product_id)

        return Response({"message": "Product removed from cart"}, status=status.HTTP_204_NO_CONTENT)        