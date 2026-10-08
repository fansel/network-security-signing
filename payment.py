from customer import Customer
from merchant import Merchant
from bank import Bank

PI = "Pay 100 DKK to MerchantX"
OI = "Order #2456: 2 items total 100 DKK"

if __name__ == "__main__":
    customer = Customer()
    signed_POMD, PIMD, OIMD = customer.sign(PI, OI)
    print(signed_POMD)

    merchant = Merchant(customer.public_key)
    merchant.merchantVerify(signed_POMD, OI, PIMD)
    print("Merchant: signature valid")

    bank = Bank(customer.public_key)
    bank.bankVerify(signed_POMD, PI, OIMD)
    print("Bank: signature valid")
