"""
Pydantic Schemas cho Rule Management API.
Tách biệt rõ ràng: Input schema (Create/Update) vs Output schema (Response).
"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────────────────────
# INPUT SCHEMAS
# ─────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    """Schema validate khi tạo một rule mới qua API."""

    action: str = Field(default="alert", description="Hành động: alert, log, drop")
    protocol: str = Field(..., description="Giao thức: tcp, udp, icmp, ip")
    src_ip: str = Field(default="any", description="IP nguồn hoặc CIDR")
    src_port: str = Field(default="any", description="Port nguồn hoặc range")
    direction: str = Field(default="->", description="Hướng: -> hoặc <>")
    dst_ip: str = Field(default="any", description="IP đích hoặc CIDR")
    dst_port: str = Field(default="any", description="Port đích, ví dụ: 80, $HTTP_PORTS, [80,443]")

    # Rule options
    msg: str = Field(..., min_length=3, description="Thông điệp cảnh báo")
    classtype: Optional[str] = Field(default=None, description="Phân loại: web-application-attack, attempted-recon...")
    severity: int = Field(default=2, ge=1, le=3, description="Mức độ: 1=High, 2=Medium, 3=Low")
    rev: int = Field(default=1, ge=1, description="Phiên bản rule")

    # Payload matching
    contents: List[str] = Field(default=[], description="Danh sách chuỗi cần tìm kiếm trong payload")
    nocase: bool = Field(default=False, description="Không phân biệt hoa/thường")
    pcre: Optional[str] = Field(default=None, description="Regular expression PCRE")

    # HTTP modifiers
    http_uri: bool = Field(default=False, description="Chỉ tìm trong HTTP URI")
    http_client_body: bool = Field(default=False, description="Chỉ tìm trong HTTP body")
    http_header: bool = Field(default=False, description="Chỉ tìm trong HTTP headers")
    http_method: Optional[str] = Field(default=None, description="Lọc theo HTTP method: GET, POST...")

    # TCP flags
    flags: Optional[str] = Field(default=None, description="TCP flags: SF, FUP, 0, F, ...")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        allowed = {"tcp", "udp", "icmp", "ip"}
        if v.lower() not in allowed:
            raise ValueError(f"protocol phải là một trong: {allowed}")
        return v.lower()

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = {"alert", "log", "drop", "pass"}
        if v.lower() not in allowed:
            raise ValueError(f"action phải là một trong: {allowed}")
        return v.lower()

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        if v not in {"->", "<>"}:
            raise ValueError("direction phải là '->' hoặc '<>'")
        return v


class RuleUpdate(BaseModel):
    """Schema validate khi cập nhật rule (partial update — tất cả field đều Optional)."""

    action: Optional[str] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[str] = None
    direction: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[str] = None
    msg: Optional[str] = None
    classtype: Optional[str] = None
    severity: Optional[int] = Field(default=None, ge=1, le=3)
    rev: Optional[int] = Field(default=None, ge=1)
    contents: Optional[List[str]] = None
    nocase: Optional[bool] = None
    pcre: Optional[str] = None
    http_uri: Optional[bool] = None
    http_client_body: Optional[bool] = None
    http_header: Optional[bool] = None
    http_method: Optional[str] = None
    flags: Optional[str] = None
    is_enabled: Optional[bool] = None


# ─────────────────────────────────────────────────────────────
# OUTPUT SCHEMAS
# ─────────────────────────────────────────────────────────────

class RuleResponse(BaseModel):
    """Schema trả về cho client sau các thao tác CRUD."""

    id: int
    sid: int
    rev: int
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    msg: str
    classtype: Optional[str]
    severity: int
    raw_rule: str
    is_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}  # Cho phép tạo từ SQLAlchemy ORM object


class RuleListResponse(BaseModel):
    """Schema trả về danh sách rules kèm thống kê."""

    total: int
    enabled: int
    disabled: int
    rules: List[RuleResponse]

