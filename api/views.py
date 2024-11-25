from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.core.files.storage import default_storage
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
from .models import Product,Order
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import models
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Product,Like
from django.shortcuts import get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from .models import OTP, CustomUser
from .models import Cart,Product,CartProduct
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import BasePermission
from django.core.exceptions import ValidationError
from rest_framework import status

class IsSuperuser(BasePermission):
    """
    Custom permission to only allow superusers to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser

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

                access_token_payload = refresh.access_token.payload
                access_token_payload['is_superuser'] = user.is_superuser  # Add this line
                
                # Store tokens in the database (optional)
                user.refresh_token = str(refresh)  # Save refresh token
                user.access_token = access_token  # Save access token (optional)
                user.save()

                return Response({
                    "refresh": str(refresh),
                    "access": access_token,
                    "message": "Login successful.",
                    "is_superuser": user.is_superuser
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "User not verified. Invalid OTP."}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Invalid credentials or user not verified."}, status=status.HTTP_401_UNAUTHORIZED)
        
class ProductView(APIView):
    permission_classes = [AllowAny]
    
        
    def get(self, request, pk=None):
        if pk:
            product = get_object_or_404(Product, pk=pk)
            data = {
                "id": product.id,
                "name": product.name,
                "description": product.description,
                "price": product.price,
                "image_url": request.build_absolute_uri(product.image.url) if product.image else None,
               
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
                    "image_url": request.build_absolute_uri(product.image.url) if product.image else None,
                }
                for product in products
            ]
            return Response(data, status=status.HTTP_200_OK)
    
    
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        image = request.FILES.get("image")

        product = Product.objects.create(
            name=data.get("name"),
            description=data.get("description"),
            price=data.get("price"),
            image=image 
            
        )
        return Response({"id": product.id, "message": "Product created successfully!","image_url": product.image.url }, status=status.HTTP_201_CREATED)

    def put(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        data = request.data
        product.name = data.get("name", product.name)
        product.description = data.get("description", product.description)
        product.price = data.get("price", product.price)
        image = request.FILES.get("image")
        if image:
            image_path = f"products/{image.name}"
            default_storage.save(image_path, image)
            product.image = image_path

        product.save()
        return Response({"message": "Product updated successfully!"}, status=status.HTTP_200_OK)
    

    def delete(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        product.delete()
        return Response({"message": "Product deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)


class ProductCreateView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated

    def post(self, request, *args, **kwargs):
        data = request.data
        
        # Extract product data
        product_name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        image = request.FILES.get('image')

        # Validate required fields
        if not product_name or not description or not price:
            return JsonResponse({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate price
        try:
            price = float(price)
            if price <= 0:
                return JsonResponse({'error': 'Price must be a positive number.'}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            return JsonResponse({'error': 'Invalid price format.'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle the image file
        image_path = None
        if image:
            allowed_types = ['image/jpeg', 'image/png', 'image/gif']
            max_size = 5 * 1024 * 1024  # 5MB

            # Validate image type
            if image.content_type not in allowed_types:
                return JsonResponse({"error": "Invalid image type. Allowed types: JPEG, PNG, GIF."}, status=status.HTTP_400_BAD_REQUEST)

            # Validate image size
            if image.size > max_size:
                return JsonResponse({"error": "Image size exceeds 5MB."}, status=status.HTTP_400_BAD_REQUEST)

            # Save the image file
            try:
                image_path = f"products/{image.name}"
                full_path = default_storage.save(image_path, ContentFile(image.read()))
            except Exception as e:
                return JsonResponse({'error': f'Error saving image: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        # Save product to the database
        try:
            product = Product.objects.create(
                name=product_name,
                description=description,
                price=price,
                image=image_path  # Save the relative path
            )
        except ValidationError as e:
            return JsonResponse({'error': f'Error creating product: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        # Return response with the product details
        image_url = request.build_absolute_url(f'{settings.MEDIA_URL}{image_path}') if image_path else None
        return JsonResponse({
            'message': 'Product added successfully!',
            'product': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': image_url
            }
        }, status=status.HTTP_201_CREATED)

class ProductListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        try:
            # Fetch all products owned by the authenticated user
            products = Product.objects.filter(owner=request.user)

            # If no products found, return a message
            if not products:
                return Response({"message": "No products found."}, status=status.HTTP_404_NOT_FOUND)

            # Initialize paginator
            paginator = PageNumberPagination()
            paginator.page_size = 10  # Number of products per page

            # Paginate the products
            paginated_products = paginator.paginate_queryset(products, request)

            # Manually construct the response data (without serializers)
            product_data = []
            for product in paginated_products:
                # Construct the image URL
                if product.image:
                    image_url = request.build_absolute_uri(f"{settings.MEDIA_URL}{product.image.name}")  # Full URL for the image
                else:
                    image_url = None

                product_data.append({
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "created_at": product.created_at,
                    "updated_at": product.updated_at,
                    "image_url": image_url,  # Include the image URL
                    "like_count": product.like_count,
                })

            # Include pagination information
            return Response({
                "count": paginator.page.paginator.count,  # Total number of products
                "page": paginator.page.number,           # Current page number
                "next": paginator.get_next_link(),       # Link to the next page
                "previous": paginator.get_previous_link(),  # Link to the previous page
                "products": product_data                 # Paginated products
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving products: {str(e)}")
            return Response({"error": "Failed to retrieve products."}, status=status.HTTP_400_BAD_REQUEST)
        
class PublicProductListView(APIView):
    permission_classes = [AllowAny]  # Allow access to everyone

    def get(self, request):
        try:
            # Fetch all products (public visibility)
            products = Product.objects.all()

            # If no products found, return a message
            if not products.exists():
                return Response({"message": "No products available."}, status=status.HTTP_404_NOT_FOUND)

            # Initialize paginator
            paginator = PageNumberPagination()
            paginator.page_size = 10  # Number of products per page

            # Paginate the products
            paginated_products = paginator.paginate_queryset(products, request)

            # Manually construct the response data (without serializers)
            product_data = []
            for product in paginated_products:
                # Construct the image URL
                if product.image:
                    image_url = request.build_absolute_uri(f"{settings.MEDIA_URL}{product.image.name}")  # Full URL for the image
                else:
                    image_url = None

                product_data.append({
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "price": product.price,
                    "created_at": product.created_at,
                    "updated_at": product.updated_at,
                    "image_url": image_url,  # Include the image URL
                    "like_count": product.like_count,
                })

            # Include pagination information
            return Response({
                "count": paginator.page.paginator.count,  # Total number of products
                "page": paginator.page.number,           # Current page number
                "next": paginator.get_next_link(),       # Link to the next page
                "previous": paginator.get_previous_link(),  # Link to the previous page
                "products": product_data                 # Paginated products
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving products: {str(e)}")
            return Response({"error": "Failed to retrieve products."}, status=status.HTTP_400_BAD_REQUEST)

class AddToCartView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)
        size = request.data.get("size")

        # Validate input data
        if not product_id or not isinstance(quantity, int) or quantity <= 0 or not size:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the product or return 404 if not found
        product = get_object_or_404(Product, id=product_id)

        # Retrieve or create the user's cart
        cart, _ = Cart.objects.get_or_create(user=request.user)

        # Check if the product already exists in the cart for the same size
        cart_product, created = CartProduct.objects.get_or_create(
            cart=cart,
            product=product,
            size=size,
            defaults={"quantity": quantity}
        )

        if not created:
            # Update the quantity if the item already exists
            cart_product.quantity += quantity
            cart_product.save()

        # Construct response data manually
        cart_items = CartProduct.objects.filter(cart=cart)
        cart_data = [
            {
                "product_id": item.product.id,
                "name": item.product.name,
                "price": float(item.product.price),
                "size": item.size,
                "quantity": item.quantity,
                "total_price": float(item.quantity * item.product.price),
            }
            for item in cart_items
        ]

        return Response({
            "message": "Product added to cart",
            "cart": cart_data  # Return the updated cart data
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
    
class CartDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the user's cart (create one if it doesn't exist)
        cart = get_object_or_404(Cart, user=request.user)

        # Retrieve all CartProducts related to this cart
        cart_items = CartProduct.objects.filter(cart=cart)

        # Prepare cart data to send back in the response
        cart_data = [
            {
                "product_id": item.product.id,
                "name": item.product.name,
                "price": float(item.product.price),
                "size": item.size,
                "quantity": item.quantity,
                "total_price": float(item.quantity * item.product.price),
                "image_url": item.product.image.url,  # Assuming `image` is a field on the Product model
            }
            for item in cart_items
        ]

        return Response({
            "cart": cart_data  # Return all cart items and their details
        }, status=status.HTTP_200_OK)

class LikeProductView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, product_id):
        try:
            # Get the product
            product = Product.objects.get(id=product_id)

            # Check if the user has already liked the product
            like, created = Like.objects.get_or_create(user=request.user, product=product)

            if not created:
                # If the like already exists, it means the user is unliking the product
                like.delete()
                product.like_count = F('like_count') - 1
                product.save()
                product.refresh_from_db()  # Update the like_count after the operation
                return Response({
                    "message": "Product unliked.",
                    "like_count": product.like_count
                }, status=status.HTTP_200_OK)
            else:
                # Otherwise, the user is liking the product
                product.like_count = F('like_count') + 1
                product.save()
                product.refresh_from_db()  # Update the like_count after the operation
                return Response({
                    "message": "Product liked.",
                    "like_count": product.like_count
                }, status=status.HTTP_200_OK)

        except Product.DoesNotExist:
            return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error liking product: {str(e)}")
            return Response({"error": "Failed to like the product."}, status=status.HTTP_400_BAD_REQUEST)

class LikedProductsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Fetch all products liked by the authenticated user."""
        user = request.user

        # Get products liked by the user based on the Like model
        liked_products = Product.objects.filter(like__user=user)

        # Prepare the list of liked products as dictionaries
        products_data = [
            {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': str(product.price),  # Ensure price is converted to a string for JSON response
                'image_url': product.image.url if product.image else None,  # Get the URL of the image if it exists
                'likes_count': product.liked_by.count(),  # Number of likes for the product
            }
            for product in liked_products
        ]

        return JsonResponse({'liked_products': products_data})

class CheckoutView(APIView):
    def post(self, request):
        user = request.user
        product_ids = request.data.get('product_ids', [])
        shipping_details = request.data.get('shipping_details', {})

        # Validate the shipping details
        if not shipping_details.get('name') or not shipping_details.get('address') or not shipping_details.get('phone'):
            return Response({'error': 'Shipping details are incomplete.'}, status=status.HTTP_400_BAD_REQUEST)

        products = Product.objects.filter(id__in=product_ids)

        if not products:
            return Response({'error': 'No valid products selected.'}, status=status.HTTP_400_BAD_REQUEST)

        total_amount = sum([product.price for product in products])

        # Create the order
        order = Order.objects.create(
            user=user, 
            total_amount=total_amount,
            shipping_name=shipping_details['name'],
            shipping_address=shipping_details['address'],
            shipping_phone=shipping_details['phone']
        )
        order.products.set(products)
        order.save()

        return Response({
            'message': 'Order placed successfully!',
            'order_id': order.id,
            'total_amount': order.total_amount,
            'status': order.status,
        }, status=status.HTTP_201_CREATED)



class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
        })

class UserProfileUploadView(View):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    @csrf_exempt  # If using csrf tokens, remove this decorator in production
    def put(self, request, *args, **kwargs):
        # Ensure the user is authenticated
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required."}, status=401)

        # Check if the request contains a file
        if 'profile_image' not in request.FILES:
            return JsonResponse({"error": "No profile image provided."}, status=400)

        # Get the user profile, create one if it doesn't exist
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)

        # Validate the image (size, type, etc.)
        profile_image = request.FILES['profile_image']
        try:
            self.validate_image(profile_image)
        except ValidationError as e:
            return JsonResponse({"error": str(e)}, status=400)

        # Save the image
        user_profile.profile_image = profile_image
        user_profile.save()

        # Return success response
        return JsonResponse({
            "message": "Profile image uploaded successfully.",
            "profile_image_url": user_profile.profile_image.url
        }, status=200)

    def validate_image(self, image):
        """Validate image size and type."""
        max_size = 5 * 1024 * 1024  # 5MB max size
        allowed_types = ['image/jpeg', 'image/png']

        # Check if image is too large
        if image.size > max_size:
            raise ValidationError("Image size exceeds the 5MB limit.")

        # Check if image type is allowed
        if image.content_type not in allowed_types:
            raise ValidationError("Only JPEG and PNG images are allowed.")