from django.urls import path
from .views import RegisterView, VerifyOTPView, LoginView
from .views import HomePage
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from .views import ProductView
from .views import ProductCreateView
from .views import AddToCartView, UpdateCartItemView, RemoveFromCartView,CartDetailView
from . import views
from .views import LikeProductView
from .views import CheckoutView
from django.conf.urls.static import static 
from django.conf import settings 
from .views import UserProfileView
from .views import PublicProductListView, UserProfileUploadView
from .views import LikedProductsView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('VerifyOTP/', VerifyOTPView.as_view(), name='VerifyOTP'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Add this line
    path('homepage/', HomePage.as_view(), name='homepage'),
    path('products/', ProductView.as_view(), name='product_list'),  # For GET (all products) and POST (create new product)
    path('products/<int:pk>/', ProductView.as_view(), name='product_detail'),  # For GET (single product), PUT (update), DELETE
    path('public-products/', PublicProductListView.as_view(), name='public-products-list'),
    path('products/', ProductCreateView.as_view(), name='product-create'),
    path('cart/add/', AddToCartView.as_view(), name='add-to-cart'), 
    path('cart/', CartDetailView.as_view(), name='cart-detail'),  # URL for fetching cart details
    path("cart/update/<int:product_id>/", UpdateCartItemView.as_view(), name="update-cart-item"),
    path("cart/remove/<int:product_id>/", RemoveFromCartView.as_view(), name="remove-from-cart"),
    path('products/<int:product_id>/like/', LikeProductView.as_view(), name='like_product'),
    path('liked-products/', LikedProductsView.as_view(), name='liked-products'),
    path('checkout/', CheckoutView.as_view(), name='checkout'),
    path('user/', UserProfileView.as_view(), name='user-profile'),
    path('user/upload-profile/', UserProfileUploadView.as_view(), name='upload-profile'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)