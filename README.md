# ZloBlocker
Блокировщик нежелательных хостов - это приложение для блокировки нежелательных доменов путем добавления их в файл hosts. Поддерживает автоматическое обновление списка доменов из различных источников. Работает на Windows и Linux.

Для сборки deb-пакета python3 setup.py --command-packages=stdeb.command bdist_deb

Для сборки под Windows pyinstaller --onedir --clean -y --noconsole --distpath ГПУТЬ_ДЛЯ_СОХРАНЕНИЯ_EXE\exe --icon zloblocker.ico --add-data "main.ui;." --name ZloBlocker --contents-directory "." main.py
