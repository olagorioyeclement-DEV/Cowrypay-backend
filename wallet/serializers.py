from rest_framework import serializers
from .models import Wallet, Transaction, Notification, Profile
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    tagname = serializers.CharField(source='profile.tagname', read_only=True)
    class Meta:
        model = User
        fields = ['id', 'last_name', 'first_name', 'tagname', 'email', 'username' ]

class WalletSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = Wallet
        fields = ['id', 'user', 'balance']

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['tagname']

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['reference', 'wallet', 'amount', 'transaction_type', 'timestamp', 'description', 'narration']

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"





