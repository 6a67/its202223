import base_class


class Sender(base_class.Connector):
    def __init__(self):
        super().parser.add_argument("--to",
                                    help="to which user the money should be transferred to", required=True, type=str)
        super().parser.add_argument("--amount",
                                    help="amount of money to transfer", required=True, type=int)
        super().parser.add_argument("--subject",
                                    help="subject of the transaction", required=True, type=str)

        super().__init__()

        self.to = self.args.to
        self.amount = self.args.amount
        self.subject = self.args.subject

    def send_money(self):
        self.connect()
        self.publish(f"/bank/transactions/{self.username}/{self.to}",
                     f"{self.amount:.2f};{self.subject}".encode())
        self.disconnect()


if __name__ == "__main__":
    sender = Sender()
    sender.send_money()
