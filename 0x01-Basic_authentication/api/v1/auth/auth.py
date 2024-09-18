#!/usr/bin/env python3
""" module Auth"""
from flask import request
from typing import List, TypeVar


class Auth:
    """class Auth"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require_auth"""
        if path is None or excluded_paths is None or not excluded_paths:
            return True

        if path[-1] != '/':
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            else:
                if path == excluded_path or path == excluded_path + '/':
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """authorization_header"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user"""
        return None