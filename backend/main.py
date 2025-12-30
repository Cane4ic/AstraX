import os
import smtplib
import secrets
import urllib.parse
import time
import requests
from fastapi.responses import RedirectResponse
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from random import randint
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from .database import Base, engine, SessionLocal
from .models import User
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

EMAIL_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("SMTP_PORT", "465"))  # 465 для SSL
EMAIL_USER = os.getenv("SMTP_USER")             # логин почты
EMAIL_PASSWORD = os.getenv("SMTP_PASSWORD")     # пароль / app password
EMAIL_FROM = os.getenv("SMTP_FROM") or EMAIL_USER

# таблицы создаются один раз при старте приложения
Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


# ---------- Pydantic-схемы ----------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    referralCode: str | None = None


class SignupResponse(BaseModel):
    ok: bool
    id: int

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    ok: bool
    id: int
    email: str

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str


class VerifyEmailResponse(BaseModel):
    ok: bool

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class OkResponse(BaseModel):
    ok: bool
    message: str | None = None

def send_reset_code_email(to_email: str, code: str):
    if not (EMAIL_HOST and EMAIL_USER and EMAIL_PASSWORD):
        raise RuntimeError("SMTP не настроен (нужны SMTP_HOST/SMTP_USER/SMTP_PASSWORD)")

    msg = EmailMessage()
    msg["Subject"] = "AstraX – код для сброса пароля"
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Код для сброса пароля: {code}\n\n"
        f"Он действует 10 минут. Если вы не запрашивали сброс — игнорируйте письмо."
    )

    with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as smtp:
        smtp.login(EMAIL_USER, EMAIL_PASSWORD)
        smtp.send_message(msg)


@app.post("/api/verify-email", response_model=VerifyEmailResponse)
def verify_email(body: VerifyEmailRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.verification_code:
        raise HTTPException(status_code=400, detail="Неверный код")

    # текущее время в UTC с tzinfo
    now = datetime.now(timezone.utc)

    # сначала проверяем срок действия
    if user.verification_expires_at and user.verification_expires_at < now:
        raise HTTPException(status_code=400, detail="Срок действия кода истёк")

    # потом сравниваем код
    if user.verification_code != body.code.strip():
        raise HTTPException(status_code=400, detail="Неверный код")

    # всё ок — помечаем как верифицированного
    user.is_verified = True
    user.verification_code = None
    user.verification_expires_at = None
    db.commit()

    return VerifyEmailResponse(ok=True)



@app.post("/api/password-reset/request", response_model=OkResponse)
def password_reset_request(body: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        # чтобы не палить существование email
        return OkResponse(ok=True, message="Если email существует — код отправлен")

    code = f"{randint(100000, 999999)}"
    user.reset_code = code
    user.reset_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()

    send_reset_code_email(user.email, code)
    return OkResponse(ok=True, message="Код отправлен")


@app.post("/api/password-reset/confirm", response_model=OkResponse)
def password_reset_confirm(body: PasswordResetConfirm, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.reset_code:
        raise HTTPException(status_code=400, detail="Неверный код")

    now = datetime.now(timezone.utc)
    if user.reset_expires_at and user.reset_expires_at < now:
        raise HTTPException(status_code=400, detail="Срок действия кода истёк")

    if user.reset_code != body.code.strip():
        raise HTTPException(status_code=400, detail="Неверный код")

    user.password_hash = pwd_context.hash(body.new_password[:72])
    user.reset_code = None
    user.reset_expires_at = None
    db.commit()

    return OkResponse(ok=True, message="Пароль изменён")


# ---------- зависимости ----------




# ---------- ручка регистрации ----------

@app.post("/api/signup", response_model=SignupResponse)
def signup(body: SignupRequest, db: Session = Depends(get_db)):
    # проверяем, есть ли пользователь с таким email
    existing = db.query(User).filter(User.email == body.email).first()

    # генерируем код заранее
    code = f"{randint(100000, 999999)}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    # 1. Пользователь существует и уже верифицирован → ошибка
    if existing and existing.is_verified:
        raise HTTPException(
            status_code=400,
            detail="Пользователь уже зарегистрирован"
        )

    # 2. Пользователь существует, но НЕ подтверждён → переотправляем код
    if existing and not existing.is_verified:
        existing.verification_code = code
        existing.verification_expires_at = expires_at
        db.commit()

        try:
            send_verification_email(existing.email, code)
        except Exception:
            raise HTTPException(500, "Не удалось отправить письмо с кодом")

        return {"ok": True, "id": existing.id}

    # 3. Новый пользователь → создаём
    password_hash = pwd_context.hash(body.password[:72])

    user = User(
        email=body.email,
        password_hash=password_hash,
        referral_code=body.referralCode or None,
        verification_code=code,
        verification_expires_at=expires_at,
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    try:
        send_verification_email(user.email, code)
    except Exception:
        raise HTTPException(500, "Не удалось отправить письмо с кодом")

    return SignupResponse(ok=True, id=user.id)

@app.post("/api/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    # ищем пользователя по email
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Неверный email или пароль")

    # проверяем хэш пароля
    if not pwd_context.verify(body.password[:72], user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный email или пароль")

    return LoginResponse(ok=True, id=user.id, email=user.email)

def send_verification_email(to_email: str, code: str):
  if not (EMAIL_HOST and EMAIL_USER and EMAIL_PASSWORD):
      # если не настроили SMTP — лучше не падать молча
      raise RuntimeError("SMTP не настроен (нужны SMTP_HOST/SMTP_USER/SMTP_PASSWORD)")

  msg = EmailMessage()
  msg["Subject"] = "AstraX – код подтверждения регистрации"
  msg["From"] = EMAIL_FROM
  msg["To"] = to_email
  msg.set_content(
      f"Ваш код подтверждения: {code}\n\n"
      f"Он действует 10 минут. Если вы не запрашивали этот код, просто игнорируйте письмо."
  )

  # SSL-соединение (smtp.gmail.com:465, например)
  with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as smtp:
      smtp.login(EMAIL_USER, EMAIL_PASSWORD)
      smtp.send_message(msg)


FINNHUB_KEY = os.getenv("FINNHUB_KEY", "")

def _tf_to_finnhub_res(tf: str) -> str:
    tf = (tf or "1m").lower()
    return {
        "1m": "1",
        "5m": "5",
        "15m": "15",
        "30m": "30",
        "1h": "60",
        "1d": "D",
        "1w": "W",
        "1mo": "M",
    }.get(tf, "1")

@app.get("/api/stocks/quotes")
def api_stocks_quotes(symbols: str):
    """
    /api/stocks/quotes?symbols=AAPL,MSFT,NVDA
    -> { "AAPL": {"price": 123.45}, ... }
    """
    if not FINNHUB_KEY:
        return {}

    out = {}
    syms = [s.strip().upper() for s in symbols.split(",") if s.strip()]
    for sym in syms:
        r = requests.get(
            "https://finnhub.io/api/v1/quote",
            params={"symbol": sym, "token": FINNHUB_KEY},
            timeout=8,
        )
        j = r.json()
        # c = current price
        if "c" in j and j["c"] is not None:
            out[sym] = {"price": float(j["c"])}
    return out


@app.get("/api/stocks/candles")
def api_stocks_candles(symbol: str, tf: str = "1m"):
    """
    /api/stocks/candles?symbol=AAPL&tf=1m
    -> [{t,o,h,l,c}, ...]  (t в миллисекундах)
    """
    if not FINNHUB_KEY:
        return []

    sym = symbol.strip().upper()
    resolution = _tf_to_finnhub_res(tf)

    to_ts = int(time.time())
    # окно истории: 3 дня (для минуток). Можешь увеличить.
    from_ts = to_ts - 3 * 24 * 60 * 60

    r = requests.get(
        "https://finnhub.io/api/v1/stock/candle",
        params={
            "symbol": sym,
            "resolution": resolution,
            "from": from_ts,
            "to": to_ts,
            "token": FINNHUB_KEY,
        },
        timeout=12,
    )
    j = r.json()
    if j.get("s") != "ok":
        return []

    t = j.get("t") or []
    o = j.get("o") or []
    h = j.get("h") or []
    l = j.get("l") or []
    c = j.get("c") or []

    n = min(len(t), len(o), len(h), len(l), len(c))
    return [
        {
            "t": int(t[i]) * 1000,   # ms
            "o": float(o[i]),
            "h": float(h[i]),
            "l": float(l[i]),
            "c": float(c[i]),
        }
        for i in range(n)
    ]


# ---------- отдаём фронтенд статикой ----------

BASE_DIR = Path(__file__).resolve().parent.parent  # папка AstraX
FRONTEND_DIR = BASE_DIR / "frontend"

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
