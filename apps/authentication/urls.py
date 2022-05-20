from django.urls import path, include
from .views import UserChangePasswordView, UserLoginView, UserProfileView, UserRegistrationView, SendPasswordResetEmailView, UserPasswordResetView,VerifyEmail
urlpatterns = [
    path('register/', UserRegistrationView.as_view(),name='register'),
    path('email-verify/', VerifyEmail.as_view(),name='email-verify'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
]