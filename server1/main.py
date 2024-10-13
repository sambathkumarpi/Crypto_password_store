from fastapi import FastAPI, HTTPException, Body, Depends
from typing import List
import csv
import secrets
from argon2 import PasswordHasher
import requests

app = FastAPI()
filename = 'users.csv'
hasher = PasswordHasher()

URL = "http://localhost:5000/encrypt"


def read_users_from_csv(filename):
    users = []
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            users.append(row)
    return users

def write_users_to_csv(users):
    with open(filename, 'w', newline='') as file:
        fieldnames = ['username', 'password_hash', 'salt']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)

def hash_password(password: str, salt: str):
    return hasher.hash(password.encode('utf-8') , salt=salt.encode('utf-8'))

def encrypt_password(password: str, salt: str):
    password_hash = hash_password(password, salt)

    data = {"password_hash": password_hash}

    response = requests.post(URL, json=data)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Encryption failed.")

    encrypted_hash = response.json()["encrypted_data"]
    return encrypted_hash

def register(new_username: str, new_password: str, confirm_password: str, users: List[dict]):
    print(len(new_password))
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password length should be greater than 8 characters.")

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match. Registration failed.")

    for user in users:
        if user['username'] == new_username:
            raise HTTPException(status_code=400, detail="Username already exists. Registration failed.")

    salt = secrets.token_hex(16)

    encrypted_hash = encrypt_password(new_password, salt)

    users.append({'username': new_username, 'password_hash': encrypted_hash, 'salt': salt})
    write_users_to_csv(users)
    return {"message": "Registration successful!"}

@app.post('/register')
async def register_route(new_username: str = Body(...), new_password: str = Body(...), confirm_password: str = Body(...)):
    users = read_users_from_csv(filename)
    return register(new_username, new_password, confirm_password, users)


def login(username: str, password: str, users: List[dict]):
    for user in users:
        if user['username'] == username:
            hashed_password = encrypt_password(password, user['salt'])
            print(hashed_password,"\n" , user['password_hash'])
            if hashed_password == user['password_hash']:
                return {"message": "Login successful!"}
            else:
                raise HTTPException(status_code=401, detail="Incorrect password. Login failed.")
    raise HTTPException(status_code=404, detail="Username not found. Login failed.")

@app.post('/login')
async def login_route(username: str = Body(...), password: str = Body(...)):
    users = read_users_from_csv(filename)
    return login(username, password, users)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
