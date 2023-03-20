from decimal import Decimal

import base_class

balance = 0


def on_message(client, userdata, msg):
    global balance

    user_from = str(msg.topic).split("/")[3]
    user_to = str(msg.topic).split("/")[4]
    subject = str(msg.payload.decode()).split(";")[1]
    amount = Decimal(str(msg.payload.decode()).split(";")[0])
    if user_from == oa.username:
        balance -= amount
    else:
        balance += amount
    print(f"| {user_from} | {user_to} | {subject} | {amount} | {balance} |")


oa = base_class.Connector()

oa.on_connect_subscribe(
    f"/bank/transactions/+/{oa.username}/+", f"/bank/transactions/{oa.username}/+/+")
oa.on_message(on_message)
oa.connect()
oa.loop_forever()
