"""remove post

Revision ID: 61e7acad8c96
Revises: d7f1401b2b02
Create Date: 2021-08-06 00:00:39.474879

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '61e7acad8c96'
down_revision = 'd7f1401b2b02'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('followers')
    op.drop_index('ix_post_timestamp', table_name='post')
    op.drop_table('post')
    op.drop_index('ix_user_username', table_name='user')
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_username'), table_name='user')
    op.create_index('ix_user_username', 'user', ['username'], unique=1)
    op.create_table('post',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('body', sa.VARCHAR(length=140), nullable=True),
    sa.Column('timestamp', sa.DATETIME(), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_post_timestamp', 'post', ['timestamp'], unique=False)
    op.create_table('followers',
    sa.Column('follower_id', sa.INTEGER(), nullable=True),
    sa.Column('followed_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['followed_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['follower_id'], ['user.id'], )
    )
    # ### end Alembic commands ###
