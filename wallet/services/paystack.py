import requests
from django.conf import settings



def verify_bank_account(account_number: str, bank_code: str) -> str | None:

    url = "https://api.paystack.co/bank/resolve"

    headers = {
        'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json',
    }

    params = {
        'account_number': account_number, 'bank_code': bank_code
    }

    try:
        paystack_response = requests.get(url, headers=headers, params=params, timeout=15)
        data = paystack_response.json()

        print("PAYSTACK RESOLVE →", paystack_response.status_code, data)

    except requests.RequestException:
        return None

    if paystack_response.status_code == 200 and data.get('status') is True:
        return data['data']['account_name']

    return None
