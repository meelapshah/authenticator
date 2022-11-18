from setuptools import setup

setup(
  name="Authenticator",
  version="1.0",
  py_modules=[ "authenticator" ],
  install_requires=[
    "termcolor"
  ],
  author="Meelap Shah",
  author_email="meelapshah@gmail.com",
  description="Generate TOTP tokens from Android Google Authenticator app's database.",
  entry_points={
    "console_scripts": [
      "authenticator = authenticator:main",
      # "fx-authenticator = authenticator:fx_addon",
    ]
  }
)
