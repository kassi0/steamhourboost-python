#!/usr/bin/env python3
import os
import sqlite3
from werkzeug.security import generate_password_hash
import getpass

# Define o caminho para o arquivo do banco de dados SQLite
DATABASE = os.path.join(os.path.dirname(__file__), "app.db")

def init_db():
    """
    Inicializa o banco de dados, criando a tabela 'users' se ela não existir.
    """
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """)
        conn.commit()
    print("Banco de dados inicializado.")

def create_user(username, password):
    """
    Cria um novo usuário com o nome e senha fornecidos.
    A senha é convertida para hash antes de ser armazenada.
    """
    password_hash = generate_password_hash(password)
    with sqlite3.connect(DATABASE) as conn:
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            print(f"Usuário '{username}' criado com sucesso!")
        except sqlite3.IntegrityError as e:
            print(f"Erro ao criar usuário: {e}")

def main():
    # Inicializa o banco de dados
    init_db()
    
    # Solicita os dados do usuário via terminal
    username = input("Digite o nome de usuário: ")
    password = getpass.getpass("Digite a senha: ")
    
    # Cria o usuário
    create_user(username, password)

if __name__ == "__main__":
    main()