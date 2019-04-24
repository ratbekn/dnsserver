import logging


def get_user_log_level_selection(msg):
    user_response = input(f'{msg} (y/n): ')
    return logging.DEBUG if user_response == 'y' else logging.ERROR
