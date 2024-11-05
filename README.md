# Packet Capture and Database Logger

## Описание

Этот проект реализует захват сетевых пакетов с использованием библиотеки `pcap` и записывает информацию о пакетах в базу данных PostgreSQL. Он позволяет фильтровать пакеты по IP-адресу и сохранять данные о них для последующего анализа.

## Установка

### Зависимости

Перед сборкой и запуском проекта убедитесь, что у вас установлены следующие зависимости:

- `libpcap` - библиотека для захвата сетевых пакетов.
- `libpq` - библиотека для работы с PostgreSQL.
- Компилятор C (например, `gcc`).

### Конфигурация
Создайте файл config.txt в корневом каталоге проекта со следующими параметрами:

```
dbname=your_database_name
user=your_username
password=your_password
host=your_host
port=your_port
```

Замените your_database_name, your_username, your_password, your_host и your_port на соответствующие значения для вашей базы данных PostgreSQL.

### Компиляция

Скомпилируйте проект с помощью следующей команды:

```bash
gcc -o packet_logger packet_logger.c -lpcap -lpq
```

## Использование
Запустите программу с помощью следующей команды:

```bash
./packet_logger
```
Программа начнет захват пакетов на интерфейсе eth0 и будет фильтровать пакеты по IP-адресу 192.168.0.252. 

Вы можете изменить этот IP-адрес в коде в строке:
```
PacketCapture capture = { .db = db, .filter_ip = "192.168.0.252" }; // Замените на ваш IP
```
## Функции
На данный момент, список функций следующий:
- Захват пакетов: Программа захватывает сетевые пакеты в реальном времени.
- Фильтрация по IP: Позволяет фильтровать пакеты по заданному IP-адресу.
- Сохранение в базу данных: Информация о каждом захваченном пакете сохраняется в базе данных PostgreSQL.
