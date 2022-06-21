"""add active student field

Revision ID: 4780158ba4af
Revises: 1635bb713cdf
Create Date: 2021-08-30 22:46:14.867578

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4780158ba4af'
down_revision = '1635bb713cdf'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('student', schema=None) as batch_op:
        batch_op.add_column(sa.Column('active', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('student', schema=None) as batch_op:
        batch_op.drop_column('active')

    # ### end Alembic commands ###
