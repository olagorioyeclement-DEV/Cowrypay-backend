from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import status, generics
from .models import Wallet, Transaction, Notification, Profile
from .serializers import UserSerializer, WalletSerializer, TransactionSerializer, NotificationSerializer, ProfileSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import transaction


#Signup Endpoint
class SignupView(APIView):
    def post(self, request):
        lastname = request.data['lastname']
        firstname = request.data['firstname']
        tagname = request.data['tagname']
        email = request.data['email']
        username = request.data['username']
        password = request.data['password']
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        elif User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        elif Profile.objects.filter(tagname=tagname).exists():
            return Response({'error': 'Tagname already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(
            last_name=lastname,
            first_name=firstname,
            username=username,
            email=email,
            password=password
        )

        Profile.objects.create(user=user, tagname=tagname)

        Wallet.objects.create(user=user) #Create Wallet for user
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
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid Credentials'}, status=400)

        if not user.check_password(password):
            return Response({'error': 'Invalid Credentials'}, status=400)

        #Create JWT Token
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Login successful',
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        })

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
        receiver_tagname = request.data.get('receiver')
        pin = request.data.get('pin')
        amount_raw = request.data.get('amount')

        #Validate Amount
        if amount_raw is None:
            return Response({'error': 'Amount is required'}, status=400)

        try:
            amount = float(amount_raw)
            if amount <= 0:
                return Response({'error': 'Amount must be greater than 0'}, status=400)
        except (ValueError, TypeError):
            return Response({'error': 'Invalid amount'}, status=400)

        #Validate Sender Wallet & Pin
        try:
            sender_wallet = Wallet.objects.get(user=sender)
        except Wallet.DoesNotExist:
            return Response({'error': 'Sender wallet not found'}, status=404)

        if not sender_wallet.verify_pin(pin):
                return Response({'error': 'Invalid Transfer PIN'}, status=400)

        #Validate Receiver
        try:
            receiver_profile = Profile.objects.get(tagname=receiver_tagname)
            receiver_user = receiver_profile.user
        except Profile.DoesNotExist:
            return Response({'error': 'Receiver not found'}, status=404)

        try:
            receiver_wallet = Wallet.objects.get(user=receiver_user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Receiver Wallet not found'}, status=404)

        #Check balance
        if sender_wallet.balance < amount:
            return Response({'error': 'Insufficient balance'}, status=400)

        #Perform atomic update
        with transaction.atomic():
            sender_wallet = Wallet.objects.select_for_update().get(user=sender)
            receiver_wallet = Wallet.objects.select_for_update().get(user=receiver_user)

            sender_wallet.balance -= amount
            receiver_wallet.balance += amount

            sender_wallet.save()
            receiver_wallet.save()

            #Transactions
            Transaction.objects.create(
                wallet=receiver_wallet,
                amount=amount,
                transaction_type='credit',
                description=f'received from {sender.profile.tagname}'
            )

            Transaction.objects.create(
                wallet=sender_wallet,
                amount=amount,
                transaction_type='debit',
                description=f'sent to {receiver_tagname}'
            )

            #Create Notification
            Notification.objects.create(
                user=receiver_user,
                message=f'You received ₦{amount}, from {sender.profile.tagname}'
            )

        return Response({
            'message': 'Transfer Successful',
            'from': sender.profile.tagname,
            'to': receiver_tagname,
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

