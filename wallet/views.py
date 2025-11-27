from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import status, generics
from .models import Wallet, Transaction
from .serializers import UserSerializer, WalletSerializer, TransactionSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

#Signup Endpoint
class SignupView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']
        email = request.data['email']
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, email=email, password=password)
        wallet.objects.create(user=user) #Create Wallet for user
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Signup successful',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

#Login Endpoint
class LoginView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']
        user = authenticate(username=username, password=password)
        if user:
            return Response({'message': 'User login successfully'})
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

#View Wallet
class WalletView(APIView):
    permission_classes = ([IsAuthenticated])

    def get(self, request):
        wallet = Wallet.objects.get(user=request.user)
        serializer = WalletSerializer(wallet)
        return Response(serializer.data)

#Set Pin
class SetPinView(APIView):
    permission_classes = ([IsAuthenticated])

    def post(self, request):
        pin = request.data.get('pin')

        if not pin or len(pin) != 4 or pin.isdigit():
            return Response({'error': 'PIN must be 4-digit number'}, status=400)

        wallet = Wallet.objects.get(user=request.user)
        wallet.set_pin(pin)
        wallet.save()
        return Response({'message': 'PIN set successfully'})

#Topup Wallet
class TopupView(APIView):
    permission_classes = ([IsAuthenticated])

    def post(self, request):
        amount = request.data['amount']
        wallet = Wallet.objects.get(user=request.user)
        wallet.balance += float(amount)
        wallet.save()
        Transaction.objects.create(wallet=wallet, amount=amount, transaction_type='credit', description='Top up')
        return Response({'message': 'Wallet top up successfully', 'balance': wallet.balance})

class TransferView(APIView):
    permission_classes = ([IsAuthenticated])

    def post(self, request):
        sender = request.user
        receiver_username = request.data.get('receiver')
        amount = float(request.data.get('amount'))
        pin = request.data.get('pin')

        #Validate Pin
        wallet = Wallet.objects.get(user=sender)
        if not wallet.verify_pin(pin):
            return Response({'error': 'Invalid Transfer PIN'}, status=400)

        #Validate Receiver
        try:
            receiver = User.objects.get(username=receiver_username)
        except User.DoesNotExist:
            return Reponse({'error': 'Receiver not found'}, status=404)

        sender_wallet = wallet
        receiver_wallet = Wallet.objects.get(user=receiver)

        #Check balance
        if sender_wallet.balance < amount:
            return Response({'error': 'Insufficient balance'}, status=400)

        #Update balance
        sender_wallet.balance -= amount
        receiver_wallet.balance += amount
        sender_wallet.save()
        receiver_wallet.save()

        #Transactions
        Transaction.objects.create(
            wallet=receiver_wallet,
            amount=amount,
            transaction_type='credit',
            description=f'received from{sender.username}'
        )

        Transaction.objects.create(
            wallet=sender_wallet,
            amount=amount,
            transaction_type='debit',
            description=f'sent to{receiver_username}'
        )

        #Create Notification
        Notification.objects.create(
            user=receiver_wallet,
            message=f'You received ₦{amount}, from {sender.username}'
        )

        return Response({
            'message': 'Transfer Successful',
            'from': sender.username,
            'to': receiver_username,
            'amount': amount,
            'balance': sender_wallet.balance
        })

class NotificationListView(APIView):
    permission_classes = ([IsAuthenticated])

    def get(self, request):
        notification = Notification.objects.filter(user=request.user).order_by ('-timestamp')
        serializer = NotificationSerializer(notification, many=True)
        return Response(serializer.data)

class LogoutView(APIView):
    permission_classes = ([IsAuthenticated])
    def post(self, request):
        try:
            refresh_token = request.data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'})
        except Exception:
            return Response({'error': 'Invalid credentials'}, status=400)

