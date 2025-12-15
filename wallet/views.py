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
from decimal import Decimal, InvalidOperation
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination


#Signup Endpoint
class SignupView(APIView):

    @swagger_auto_schema(
        tags=['Auth'],
        operation_summary='Create a user account',
        operation_description='Register a new user and automatically create a wallet.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'lastname': openapi.Schema(type=openapi.TYPE_STRING, example='Olagorioye'),
                'firstname': openapi.Schema(type=openapi.TYPE_STRING, example='Clement'),
                'tagname': openapi.Schema(type=openapi.TYPE_STRING, example='Lekan01'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, example='morakinyo2025@gmail.com'),
                'username': openapi.Schema(type=openapi.TYPE_STRING, example='Crowner2025'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, example='mypassword123'),
            },
            required=['lastname', 'firstname', 'tagname', 'email', 'username', 'password'],
        ),
        responses={
            201: "Signup successful",
            400: 'Username already exists',
        }
    )

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

    @swagger_auto_schema(
        tags=['Auth'],
        operation_summary='User login',
        operation_description='Authenticate a user and returns a JWT access and refresh token.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, example='Crowner2025'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, example='mypassword123'),
            },
            required=['username', 'password'],
        ),
        responses={200: 'User login successful'}
    )

    def post(self, request):
        username = request.data['username']
        password = request.data['password']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid Credentials'}, status=400)

        if not user.check_password(password):
            return Response({'error': 'Invalid Credentials'}, status=400)

        try:
            wallet = Wallet.objects.get(user=user)
        except Wallet.DoesNotExist:
            return Response({"error": "Wallet not found"}, status=404)

        #Create JWT Token
        refresh = RefreshToken.for_user(user)
        return Response({
            'message': 'Login successful',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'pin_set': wallet.pin_set,
        })

#View Wallet
class WalletView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = ([IsAuthenticated])

    @swagger_auto_schema(
        tags=['Wallet'],
        operation_summary='Get wallet balance',
        security=[{'Bearer':[]}],
        responses={200: 'Wallet retrieved successfully'},
    )

    def get(self, request):
        wallet = Wallet.objects.get(user=request.user)
        serializer = WalletSerializer(wallet)
        return Response(serializer.data)

#Set Pin
class SetPinView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = ([IsAuthenticated])

    @swagger_auto_schema(
        tags=['Transfer'],
        operation_summary='Set 4-digit transfer pin',
        security=[{'Bearer':[]}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'pin': openapi.Schema(type=openapi.TYPE_STRING, example='1234')
            },
            required=['pin']
        ),
        responses={200: 'PIN set successful'}
    )

    def post(self, request):
        pin = request.data.get('pin')

        if not pin or len(pin) != 4 or not pin.isdigit():
            return Response({'error': 'PIN must be 4-digit number'}, status=400)

        wallet = Wallet.objects.get(user=request.user)
        wallet.set_pin(pin)
        wallet.pin_set = True
        wallet.save()
        return Response({'message': 'PIN set successfully'})

#Topup Wallet
class TopupView(APIView):
    permission_classes = ([IsAuthenticated])
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        tags=['Wallet'],
        operation_summary='Top-up wallet',
        security=[{'Bearer':[]}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, example=500)
            },
            required=['amount']
        ),
        responses={200: 'Top-up successful'}
    )

    def post(self, request):
        amount_raw = request.data.get('amount')
        if not amount_raw:
            return Response ({'error': 'Amount is required'}, status=400)
        try:
            amount = Decimal(amount_raw.replace(',', ''))
            if amount <= 0:
                return Response({'error': 'Amount must be greater than 0'}, status=400)
        except(ValueError, InvalidOperation):
            return Response({'error': 'Invalid amount'}, status=400)

        wallet = Wallet.objects.get(user=request.user)
        wallet.balance += amount
        wallet.save()

        Transaction.objects.create(
            wallet=wallet,
            amount=amount,
            transaction_type='Credit',
            description='Top up'
        )

        return Response({
            'message': 'Top up successfully',
            'balance': str(wallet.balance)
        })

class TransferView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = ([IsAuthenticated])

    @swagger_auto_schema(
        tags=['Transfer'],
        operation_summary='Transfer to another user using tagname',
        security=[{'Bearer':[]}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'receiver': openapi.Schema(type=openapi.TYPE_STRING, example='crowner'),
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, example=10000),
                'pin': openapi.Schema(type=openapi.TYPE_STRING, example='1234'),
                'narration': openapi.Schema(type=openapi.TYPE_STRING, example='Payment for food')
            },
            required=['receiver', 'amount', 'pin']
        ),
        responses={200: 'Transfer successful'}
    )

    def post(self, request):
        sender = request.user
        receiver_tagname = request.data.get('receiver')
        pin = request.data.get('pin')
        amount_raw = request.data.get('amount')
        narration = request.data.get('narration', '')

        #Validate Amount
        if amount_raw is None:
            return Response({'error': 'Amount is required'}, status=400)

        try:
            amount = Decimal(str(amount_raw).replace(',', ''))
            if amount <= 0:
                return Response({'error': 'Amount must be greater than 0'}, status=400)
        except InvalidOperation:
            return Response({'error': 'Invalid amount format'}, status=400)

        #Verify Receiver is not User
        sender_profile = Profile.objects.get(user=sender)
        if receiver_tagname == sender_profile.tagname:
            return Response({'error': 'You cannot transfer to yourself'}, status=400)

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
            credit_tx = Transaction.objects.create(
                wallet=receiver_wallet,
                amount=amount,
                transaction_type='credit',
                description=f'received from {sender.profile.tagname}',
                narration=narration,
            )

            debit_tx = Transaction.objects.create(
                wallet=sender_wallet,
                amount=amount,
                transaction_type='debit',
                description=f'sent to {receiver_tagname}',
                narration=narration,
            )


            #Create Notification
            Notification.objects.create(
                user=receiver_user,
                message=f'You received Ϛ{amount}, from {sender.profile.tagname}'
            )

            Notification.objects.create(
                user=sender_profile.user,
                message=f'You sent Ϛ{amount}, to {receiver_tagname}'
            )

        return Response({
            'message': 'Transfer Successful',
            'from': sender.profile.tagname,
            'to': receiver_tagname,
            'amount': str(amount),
            'balance': str(sender_wallet.balance),
            'reference': debit_tx.reference
        })

class VerifyTagView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        tagname = request.query_params.get('tagname')

        if not tagname:
            return Response({'error': 'Tagname is required'}, status=400)
        try:
            profile = Profile.objects.get(tagname=tagname)
        except Profile.DoesNotExist:
            return Response({'error': 'User not found'}, status=400)
        user = profile.user

        return Response({
            'fullname': f'{user.first_name} {user.last_name}',
            'tagname': tagname
        })

class NotificationListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = ([IsAuthenticated])

    @swagger_auto_schema(
        tags=['Notifications'],
        operation_summary='Get all notifications',
        security=[{'Bearer':[]}],
    )

    def get(self, request):
        notification = Notification.objects.filter(user=request.user).order_by ('-timestamp')
        serializer = NotificationSerializer(notification, many=True)
        return Response(serializer.data)

class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = ([IsAuthenticated])

    @swagger_auto_schema(
        tags=['Auth'],
        operation_summary='Logout user',
        operation_description='Invalidates user refresh token so it can not be used again.',
        security=[{'Bearer':[]}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, example='refresh_token'),
            },
            required=['refresh_token']
        ),
        responses={
            201: 'Logout Successful',
            400: 'Invalid or expired refresh token',
        }
    )

    def post(self, request):
        try:
            refresh_token = request.data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful'})
        except Exception:
            return Response({'error': 'Invalid credentials'}, status=400)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size =100

class TransactionListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Transaction'],
        operation_summary='Get transaction history (filterable, paginated)',
        security=[{'Bearer': []}],
        responses={200: 'List of transactions'}
    )

    def get(self, request):

        try:
            wallet = Wallet.objects.get(user=request.user)
        except Wallet.DoesNotExist:
            return Response({'error': 'Wallet not found'})

        qs = Transaction.objects.filter(wallet=wallet).order_by('-timestamp')

        #Filters:
        tx_type = request.query_params.get("type") #Credit/Debit all
        q = request.query_params.get('q') #Search in description, reference
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')

        if tx_type in ['credit', 'debit']:
            qs = qs.filter(transaction_type=tx_type)

        if q:
            qs = qs.filter(
                Q(description__icontains=q) |
                Q(reference__icontains=q)
            )

        if date_from:
            qs = qs.filter(timestamp__date__gte=date_from)
        if date_to:
            qs = qs.filter(timestamp__date__lte=date_to)

        #pagination
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = TransactionSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

class TransactionDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=['Transaction'],
        operation_summary='Get transaction details by reference or id',
        security=[{'Bearer': []}],
    )

    def get(self, request, identifier):
        #identifier can be numeric id or reference string
        try:
            if identifier.isdigit():
                tx = Transaction.objects.get(id=int(identifier), wallet__user=request.user)
            else:
                tx = Transaction.objects.get(reference=identifier, wallet__user=request.user)
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=400)

        serializer = TransactionSerializer(tx)
        return Response(serializer.data)



