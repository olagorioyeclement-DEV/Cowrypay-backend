from django.urls import path
from .views import SignupView, LoginView, WalletView, TopupView, LogoutView, SetPinView, TransferView, NotificationListView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('wallet/', WalletView.as_view(), name='wallet'),
    path('topup/', TopupView.as_view(), name='topup'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('set-pin/', SetPinView.as_view(), name='set_pin'),
    path('transfer/', TransferView.as_view(), name='transfer'),
    path('notifications/', NotificationListView.as_view(), name='notifications')
]