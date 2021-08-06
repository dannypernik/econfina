"""add student table

Revision ID: d7f1401b2b02
Revises: 01cc04ac7535
Create Date: 2021-08-05 00:47:13.568450

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7f1401b2b02'
down_revision = '01cc04ac7535'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('student',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=64), nullable=True),
    sa.Column('parent_email', sa.String(length=64), nullable=True),
    sa.Column('tz', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )

    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('first_name', sa.String(length=64), nullable=True),
    sa.Column('last_name', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=64), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('last_viewed', sa.DATETIME(), nullable=True),
    sa.Column('about_me', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_index(op.f('ix_user_first_name'), 'user', ['first_name'], unique=False)
    op.create_index(op.f('ix_user_last_name'), 'user', ['last_name'], unique=False)
    op.create_index(op.f('ix_user_timestamp'), 'user', ['timestamp'], unique=False)
    #op.create_table('student',
    #sa.Column('id', sa.Integer(), nullable=False),
    #sa.Column('first_name', sa.String(length=32)),
    #sa.Column('last_name', sa.String(length=32)),
    #sa.Column('username', sa.String(length=64)),
    #sa.Column('email', sa.String(length=64)),
    #sa.Column('phone', sa.String(length=32)),
    #sa.Column('password_hash', sa.String(length=128)),
    #sa.Column('timestamp', sa.DateTime(length=32)),
    #sa.Column('posts'),
    #sa.Column('about_me'),
    #sa.Column('last_viewed')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('student')
    # ### end Alembic commands ###
