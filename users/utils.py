import secrets


def generate_reset_token():
    return secrets.token_hex(32)



if __name__=="__main__":
    print(generate_reset_token())