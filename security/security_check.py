#!/usr/bin/env python3

def main():
    print("Web Check")
    url = input("Adres strony lub domena: ").strip()

    if not url:
        print("Błąd: brak adresu.")
        return

    print(f"Sprawdzam: {url}")


if __name__ == "__main__":
    main()
