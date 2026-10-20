from .db import find_user


class UserService:
    def lookup(self, term):
        return find_user(term)
