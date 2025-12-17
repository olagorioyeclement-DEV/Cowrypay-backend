from django.urls import path
from .views import (
    SignupView,
    LoginView,
    WalletView,
    TopupView,
    LogoutView,
    SetPinView,
    TransferView,
    NotificationListView,
    VerifyTagView,
    TransactionListView,
    TransactionDetailView,
    UserSettingsView,
    ChangePinView,
)


urlpatterns = [

    #Auth Endpoints
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    #Wallet Endpoints
    path('wallet/', WalletView.as_view(), name='wallet'),
    path('topup/', TopupView.as_view(), name='topup'),

    #Transfer Endpoints
    path('set-pin/', SetPinView.as_view(), name='set_pin'),
    path('transfer/', TransferView.as_view(), name='transfer'),
    path('verify-tag/', VerifyTagView.as_view(), name='verify_tag'),
    path('transactions/', TransactionListView.as_view(), name='transactions'),
    path('transactions/<str:identifier>/', TransactionDetailView.as_view(), name='transaction_detail'),
    path('change-pin/', ChangePinView.as_view(), name='change_pin'),

    #Notifications Endpoints
    path('notifications/', NotificationListView.as_view(), name='notifications'),

    #Settings Endpoints
    path('settings/', UserSettingsView.as_view(), name='user_settings')
]