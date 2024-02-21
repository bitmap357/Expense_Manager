from .models import db, User, Expense


@click.command('db')
@click.option('--init', 'init', is_flag=True, help='Initialize migration repository')
@click.option('--migrate', 'migrate', is_flag=True, help='Generate migration script')
@click.option('--upgrade', 'upgrade', is_flag=True, help='Apply migrations')
