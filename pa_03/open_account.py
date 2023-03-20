import base_class

oa = base_class.Connector()

oa.connect()
oa.publish(f"/bank/account/open/{oa.username}", None)
oa.disconnect()
