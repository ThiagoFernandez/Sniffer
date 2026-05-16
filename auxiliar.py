from datetime import datetime


def save_file(data, idx):
    with open("subnetting_results.txt", "at", encoding="UTF-8") as f:
        if idx == 0:
            now = datetime.now()
            f.write(f"{'=' * 40} {now}\n")
        line = ""
        for key, value in data.items():
            line += f"{key}: {value}; "
        f.write(line + "\n")


def show_options(options):
    for idx, value in enumerate(options):
        print(f"{idx + 1}. {value}")


def validate_number(options):
    while True:
        try:
            option = int(input("Choose an option: "))
        except ValueError:
            print("The value must be a number | Try again")
        else:
            if option < 1 or option > len(options) + 1:
                print(f"The option must be between 1-{len(options) + 1} | Try again")
            elif option == len(options) + 1:
                return -1
            else:
                return option


def validate_numberv2():
    while True:
        try:
            option = int(input("Write a number(-1 to exit): "))
        except ValueError:
            print("The value must be a number | Try again")
        else:
            if option == -1:
                return -1
            else:
                if option < 0:
                    print("The value cannot be negative | Try again")
                else:
                    return option


def validate_string(options, text, type):
    while True:
        string = input(f"{text}('*' to go back to the menu): ")
        if string.strip() == "":
            print("Only blank space as text is invalid | Try again")
        elif string.strip() == "*":
            return -1
        elif string in options:
            print("There is one with the same name | Try again")
        elif not string.endswith(".mp3") and type == 0:
            print("The name needs to end with a '.mp3' | Try again")
        else:
            return string


def validate_command(options, text):
    while True:
        string = input(f"{text}('*' to go back to the menu): ")
        if string.strip() == "":
            print("Only blank space as text is invalid | Try again")
        elif string.strip() == "*":
            return -1
        elif string not in options:
            print("That's not a valid command | Try again")
        else:
            return string


def greeting_text(text):
    print(f"{' ' + text + ' ':-^60}")


def validate_string_v2(text):
    while True:
        string = input(f"{text}('*' to go back to the menu): ")
        if string.strip() == "":
            print("Only blank space as text is invalid | Try again")
        elif string.strip() == "*":
            return -1
        else:
            return string
