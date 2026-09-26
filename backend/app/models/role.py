from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin


class Role(UUIDTimestampMixin, Base):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="role",
    )