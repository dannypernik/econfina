"""item.booqable_id

Revision ID: 8316875227c5
Revises: a12bb1957546
Create Date: 2023-09-16 23:36:49.284783

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8316875227c5'
down_revision = 'a12bb1957546'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.add_column(sa.Column('booqable_id', sa.String(length=32), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.drop_column('booqable_id')

    # ### end Alembic commands ###
