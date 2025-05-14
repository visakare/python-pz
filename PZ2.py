# 1. Створіть базовий клас User (Користувач) з атрибутами: username, password_hash, is_active, метод verify_password(password), який приймає пароль та порівнює його з password_hash.
# 2. Створіть підкласи, що представляють різні ролі користувачів, наприклад:
# ○	Administrator, який успадковує від User та може мати додаткові атрибути або методи, пов'язані з адмініструванням системи (наприклад, список дозволів).
# ○	RegularUser, який також успадковує від User та може мати специфічні для звичайних користувачів атрибути (наприклад, остання дата входу).
# ○	GuestUser, який є підкласом User та може мати обмежені права доступу.
# 3. Створіть клас AccessControl (Контроль доступу) з атрибутами:
# ○	users (словник, де ключами є імена користувачів, а значеннями - об'єкти класів користувачів).
# ○	Метод add_user(user), який додає нового користувача до системи.
# ○	Метод authenticate_user(username, password), який перевіряє, чи існує користувач з таким ім'ям та чи правильний введений пароль. Повертає об'єкт користувача у разі успішної аутентифікації, і None у разі невдачі.

import hashlib
from datetime import datetime
# 1. Створення базового класу User з атрибутами та методами для обробки даних користувача
class User:

    # Ініціалізація користувача з іменем, паролем та статусом активності
    def __init__(self, username, password, is_active = True):
        self.username = username # Ім'я користувача
        self.password_hash = self.hash_password(password) # Захешований пароль
        self.is_active = is_active # Статус активності акаунта

    # Метод для хешування пароля за допомогою SHA256
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    # Метод для перевірки введеного пароля за допомогою хешованого пароля
    def verify_password(self, password):
        return self.hash_password(password) == self.password_hash

    # Метод для повернення рядка з інформацією про користувача
    def __str__(self):
        return f"User(Username: '{self.username}', Active: {self.is_active})"

# 2. Створення підкласів, що представляють різні ролі користувачів
# Клас Administrator успадковує від User й може мати додаткові дозволи
class Administrator(User):
    #  Ініціалізація адміністратора з додатковим атрибутом дозволів
    def __init__(self, username, password, is_active = True, permissions = None):
        super().__init__(username, password, is_active) # Виклик конструктора батьківського класу
        # Якщо дозволи не задані — встановлюємо за замовчуванням "full_control"
        self.permissions = permissions if permissions is not None else ["full_control"]
        print(f"Administrator '{self.username}' created with permissions: {self.permissions}")

    # Метод для надання дозволу адміністратору
    def grant_permission(self, permission):
        # Перевіряє, чи немає вже вказаного дозволу в списку дозволів адміністратора.
        # Якщо дозволу ще немає в списку, він додається.
        if permission not in self.permissions:
            self.permissions.append(permission)
            print(f"Permission '{permission}' granted to administrator '{self.username}'.")
        else:
            print(f"Administrator '{self.username}' already has permission '{permission}'.")

    # Метод для відкликання дозволу від адміністратора
    def revoke_permission(self, permission):
        # Перевіряє, чи існує дозвіл у списку дозволів адміністратора.
        # Якщо дозвіл знайдено, він видаляється зі списку.
        if permission in self.permissions:
            self.permissions.remove(permission)
            print(f"Permission '{permission}' revoked from administrator '{self.username}'.")
        else:
            print(f"Administrator '{self.username}' not has permission '{permission}'.")

    # Повернення рядка з інформацією про адміністратора
    def __str__(self):
        return f"Administrator(Username: '{self.username}', Active: {self.is_active}, Permission: {self.permissions})"

# Клас RegularUser успадковує від User й може мати додаткові атрибути, наприклад, дату останнього входу
class RegularUser(User):
    # Ініціалізація звичайного користувача з додатковим атрибутом дати останнього входу
    def __init__(self, username, password, is_active = True, last_login_date = None):
        super().__init__(username, password, is_active) # Виклик конструктора батьківського класу
        # Якщо дата входу не вказана — встановити поточну
        if last_login_date is None:
            last_login_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_login_date = last_login_date
        print(f"Regular User '{self.username}' created, last login: {self.last_login_date}.")

    # Метод для оновлення дати останнього входу
    def update_last_login_date(self, login_date):
        self.last_login_date = login_date
        print(f"For user '{self.username}' updated the date of last login: {self.last_login_date}.")

    # Повернення рядка з інформацією про звичайного користувача
    def __str__(self):
        return f"Regular User(Username: '{self.username}', Active: {self.is_active}, Last login date: '{self.last_login_date}')"

# Клас GuestUser успадковує від User й має обмежений рівень доступу
class GuestUser(User):
    # Ініціалізація гостя з обмеженим доступом
    def __init__(self, username = "Guest", password = ""):
        super().__init__(username, password, is_active = True) # Виклик конструктора батьківського класу
        self.access_level = "limited" # Рівень доступу для гостей
        print(f"Guest User '{self.username}' created with access level: {self.access_level}.")

    # Повернення рядка з інформацією про гостя
    def __str__(self):
        return f"Guest User(Username: '{self.username}', Active: {self.is_active}, Access level: '{self.access_level}')"

# 3. Створення класу AccessControl для управління системою користувачів
class AccessControl:
    def __init__(self):
        self.users = {} # Словник користувачів: ключ — username, значення — об'єкт користувача
        print("Access control system created.")

    # Метод для додавання користувача до системи
    def add_user(self, user):
        if user.username in self.users:
            print(f"Error: User with name '{user.username}' already exists.")
            return False
        self.users[user.username] = user
        print(f"User '{user.username}' successfully added to the system.")

    # Метод для аутентифікації користувача за іменем і паролем
    def authenticate_user(self, username, password):
        user = self.users.get(username) # Отримання об'єкту користувача за іменем
        if user:
            if not user.is_active:
                print(f"Authentication failed: Account '{username}' not active.")
                return None
            if user.verify_password(password):
                print(f"Authentication successful for user '{username}'.")
                if isinstance(user, RegularUser): # Якщо користувач звичайний, оновлюємо дату останнього входу
                    user.update_last_login_date(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                return user
            else:
                print(f"Authentication failed: Incorrect password for '{username}'.")
                return None
        else:
            print(f"Authentication failed: User '{username}' not found.")
        return None

    # Метод для отримання користувача за іменем
    def get_user(self, username):
        return self.users.get(username)

    # Метод для виведення списку користувачів
    def print_users_dict(self):
        print("\n User list")
        for username, user_obj in self.users.items():
            print(f"{username}: {user_obj}")

# 4. Основне виконання для створення користувачів, додавання їх до системи доступу та аутентифікації
if __name__ == "__main__":
    print("\n Creating Users")
    # Створення різних типів користувачів
    admin = Administrator("admin", "km27uh%_Tf", permissions = ["manage_users", "view_logs"])
    user1 = RegularUser("Oliver", "YGu7*f64", last_login_date = "2025-05-04 12:35:56")
    user2 = RegularUser("Florence", "l,*&3RDqz", is_active = False, last_login_date = "2025-05-12 06:05:14")
    guest1 = GuestUser()
    guest2 = GuestUser("Guest2")

    # Створення системи доступу та додавання користувачів
    print("\n Creating an access control system and adding users")
    access_system = AccessControl() # Створення системи доступу
    access_system.add_user(admin) # Додавання адміністратора
    access_system.add_user(user1) # Додавання звичайних користувачів
    access_system.add_user(user2)
    access_system.add_user(guest1) # Додавання гостей
    access_system.add_user(guest2)

    access_system.add_user(RegularUser("Ivy", "JWD4^grt7")) # Додавання нового користувача
    access_system.add_user(RegularUser("Florence", "WEcs08*jo")) # Спроба додати Florence ще раз (тут буде помилка)

    # Аутентифікація користувачів
    print("\nAuthentication")
    authenticated_admin = access_system.authenticate_user("admin", "km27uh%_Tf")
    if authenticated_admin:
        print(f"Congratulations, {authenticated_admin.username}! Your permissions: {authenticated_admin.permissions}")
        authenticated_admin.grant_permission("backup_system")

    print("-" * 60)
    authenticated_user = access_system.authenticate_user("Oliver", "YGu7*f64")
    if authenticated_user:
        print(f"Congratulations, {authenticated_user.username}! Your last login: {authenticated_user.last_login_date}")

    print("-" * 60)
    access_system.authenticate_user("Ivy", "kjnhER4") # Невірний пароль

    print("-" * 60)
    access_system.authenticate_user("Oscar", ".kj7#hgy") # Користувача не існує

    print("-" * 60)
    access_system.authenticate_user("Florence", "l,*&3RDqz") # Неактивний користувач

    print("-" * 60)
    authenticated_guest = access_system.authenticate_user("Guest", "")
    if authenticated_guest:
        print(f"Congratulations, {authenticated_guest.username}! Your access level: {authenticated_guest.access_level}")

    # Додаткові дії з адміністратором (відкликання дозволів)
    print("\n Additional actions with administrator")
    retrieved_admin = access_system.get_user("admin")
    if isinstance(retrieved_admin, Administrator):
        print(f"Current permissions for {retrieved_admin.username}: {retrieved_admin.permissions}")
        retrieved_admin.revoke_permission("view_logs")
        print(f"Updated permissions for {retrieved_admin.username}: {retrieved_admin.permissions}")

    # Виведення всіх користувачів
    access_system.print_users_dict()