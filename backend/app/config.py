import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "CloudPosture"
    DEMO_MODE: bool = True
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"

    class Config:
        env_file = ".env"


settings = Settings()
