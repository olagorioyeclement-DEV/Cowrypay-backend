from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
import uuid
from django.utils import timezone


class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    transfer_pin = models.CharField(max_length=255, null=True, blank=True)
    pin_set = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s wallet"

    def set_pin(self, pin):
        self.transfer_pin = make_password(pin)

    def verify_pin(self, pin):
        return check_password(pin, self.transfer_pin)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    tagname = models.CharField(max_length=30, unique=True)

    def __str__(self):
        return self.tagname

class Transaction(models.Model):
    TRANSACTION_TYPE = (
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    )
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    transaction_type = models.CharField(max_length=6, choices=TRANSACTION_TYPE)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=255, blank=True)
    reference = models.CharField(max_length=90, blank=True, unique=True)
    narration = models.CharField(max_length=255, blank=True)

    def save(self, *args, **kwargs):
        if not self.timestamp:
            self.timestamp = timezone.now()

        if not self.reference:
            self.reference = self.generate_unique_reference()
        super().save(*args, **kwargs)

    def generate_unique_reference(self):
        date_part = timezone.now().strftime('%Y%m%d')
        while True:
            random_part = uuid.uuid4().hex[:8].upper()
            ref = f'TRX-{date_part}-{random_part}'
            if not Transaction.objects.filter(reference=ref).exists():
                return ref

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} for {self.wallet.user.username} ({self.reference})"

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.CharField(max_length=255)
    is_read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username} - {self.message}'