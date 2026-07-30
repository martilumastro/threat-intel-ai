#!/usr/bin/env python
"""Django's command-line utility for administrative tasks.

It is the main entry point for running Django administrative commands. manage.py allows Python to know:
which Django project to load;
which settings to use;
which command to execute.

It can be seen as a command-line "control panel" for managing the Django project."""

# os: used to interact with the operating system. In this file, it is used to set an environment variable
import os

# sys: Allows interaction with arguments passed from the command line
import sys


# main function of the file. Everything needed to start Django is executed inside here
def main():
    
    """Run administrative tasks.
    Sets an environment variable named: DJANGO_SETTINGS_MODULE
    with value: threat_intel_api.settings"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_intel_api.settings')

    """Tries to import the function: execute_from_command_line
    This function is the heart of Django commands. 
    It is what interprets commands such as: 
    runserver or migrate
    and executes them."""
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        """ If Python fails to import Django, it enters this block. This can happen if:
            Django is not installed;
            the virtual environment is not active;
            the Python path is misconfigured.
        """
        raise ImportError(
            # A custom error is raised
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc # Used to have a more complete trace of the issue during debugging.
    # Takes the terminal arguments: sys.argv and passes them to the Django management system.
    execute_from_command_line(sys.argv)

""" This condition checks if the file was executed directly.
In Python, every file has a special variable: __name__
If the file is executed directly: python manage.py
then: __name__ == "__main__"
so it calls: main()

If instead the file is imported from another module: import manage
this part is not executed."""
if __name__ == '__main__':
    main()
