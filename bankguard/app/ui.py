"""Demo UI only. No finance logic lives here."""


def render_payment_screen():
    return "Payment screen: enter destination token and amount. The server decides the rest."


def main():
    print(render_payment_screen())


if __name__ == "__main__":
    main()
