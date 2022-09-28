"""post_update check

Revision ID: 0bb68bfc8f9f
Revises: 6830f901585d
Create Date: 2022-09-27 16:51:19.886132

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0bb68bfc8f9f'
down_revision = '6830f901585d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('location', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('role', sa.String(length=24), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(length=24), nullable=True))
        batch_op.add_column(sa.Column('timezone', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('tutor_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_user_role'), ['role'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_status'), ['status'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_user_tutor_id_user'), 'user', ['tutor_id'], ['id'])
        batch_op.create_foreign_key(batch_op.f('fk_user_parent_id_user'), 'user', ['parent_id'], ['id'])
        batch_op.drop_column('username')
        batch_op.drop_column('about_me')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('about_me', sa.VARCHAR(length=500), nullable=True))
        batch_op.add_column(sa.Column('username', sa.VARCHAR(length=64), nullable=True))
        batch_op.drop_constraint('fk_user_tutor_id_user', type_='foreignkey')
        batch_op.drop_constraint('fk_user_parent_id_user', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_user_status'))
        batch_op.drop_index(batch_op.f('ix_user_role'))
        batch_op.drop_column('tutor_id')
        batch_op.drop_column('timezone')
        batch_op.drop_column('status')
        batch_op.drop_column('role')
        batch_op.drop_column('parent_id')
        batch_op.drop_column('location')

    # ### end Alembic commands ###
