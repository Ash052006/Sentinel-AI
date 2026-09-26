from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin


class User(UUIDTimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
    )

    role_id: Mapped[object] = mapped_column(
        ForeignKey("roles.id"),
        nullable=False,
    )

    role: Mapped["Role"] = relationship(
        back_populates="users",
    )