"""temp add temptestdate

Revision ID: 97b6bf103318
Revises: 0bb68bfc8f9f
Create Date: 2022-09-28 14:16:02.211417

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '97b6bf103318'
down_revision = '0bb68bfc8f9f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('temp_test_date',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('test_date_id', sa.Integer(), nullable=False),
    sa.Column('is_registered', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['test_date_id'], ['test_date.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'test_date_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('temp_test_date')
    # ### end Alembic commands ###