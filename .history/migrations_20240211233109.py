from flask import Flask 
from flask_migrate import Migrate
from .app import app, db
from .models import db, User, Post, Expense # import models
migrate = Migrate(app, db)

# Migration commands
import click

@click.command('db')
@click.option('--init', 'init', is_flag=True, help='Initialize migration repository')
@click.option('--migrate', 'migrate', is_flag=True, help='Generate migration script')
@click.option('--upgrade', 'upgrade', is_flag=True, help='Apply migrations')
def db_commands(init, migrate, upgrade):

  if init:
    Migrate(app, db).init() # Initializes migration repo

  if migrate:
    Migrate(app, db).migrate() # Generate migration script

  if upgrade:
    Migrate(app, db).upgrade() # Run migrations