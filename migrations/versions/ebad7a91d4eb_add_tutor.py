"""add tutor

Revision ID: ebad7a91d4eb
Revises: 4057880499ce
Create Date: 2022-03-10 01:33:11.406210

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ebad7a91d4eb'
down_revision = '4057880499ce'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('student', schema=None) as batch_op:
        #batch_op.drop_index('ix_student_last_name')
        #batch_op.add_column(sa.Column('tutor_id', sa.Integer(), nullable=False))
        #batch_op.drop_constraint('fk_student_tutor_id_user', type_='foreignkey')
        batch_op.create_foreign_key(batch_op.f('fk_student_tutor_id_user'), 'tutor', ['tutor_id'], ['id'])

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('hourly_rate')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hourly_rate', sa.INTEGER(), nullable=True))

    with op.batch_alter_table('student', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('fk_student_tutor_id_user', 'user', ['tutor_id'], ['id'])
        batch_op.create_index('ix_student_last_name', ['last_name'], unique=False)

    # ### end Alembic commands ###
